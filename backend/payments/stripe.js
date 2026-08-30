import Stripe from 'stripe';
import { recordSubscription } from './subscriptions.js';
import { createLicenseCode, getLicenseCodeBySubscription } from './licenseCodes.js';
import { setOrgPlanStatus } from '../auth/organizations.js';

let cachedClient = null;

// Lazily constructed, not at import time — importing this module (e.g. from server.js
// or the test suite) must not throw just because Stripe isn't configured yet, in dev or
// self-hosted deployments that don't want billing at all.
function getClient() {
  if (!process.env.STRIPE_SECRET_KEY) return null;
  if (!cachedClient) cachedClient = new Stripe(process.env.STRIPE_SECRET_KEY);
  return cachedClient;
}

export function isConfigured() {
  return Boolean(process.env.STRIPE_SECRET_KEY && process.env.STRIPE_PRICE_ID_TEAM && process.env.STRIPE_WEBHOOK_SECRET);
}

export async function retrieveCheckoutSession(sessionId) {
  const client = getClient();
  if (!client) throw new Error('Stripe is not configured (STRIPE_SECRET_KEY unset)');
  return client.checkout.sessions.retrieve(sessionId);
}

export async function createCheckoutSession(email, { successUrl, cancelUrl }) {
  const client = getClient();
  if (!client) throw new Error('Stripe is not configured (STRIPE_SECRET_KEY unset)');
  return client.checkout.sessions.create({
    mode: 'subscription',
    customer_email: email,
    line_items: [{ price: process.env.STRIPE_PRICE_ID_TEAM, quantity: 1 }],
    success_url: successUrl,
    cancel_url: cancelUrl
  });
}

/**
 * Verifies the raw request body against Stripe's signature (throws if it doesn't match —
 * callers must not trust an unverified body, since anyone can POST arbitrary JSON to a
 * public webhook URL claiming to be Stripe), then records the resulting subscription
 * state. Returns the verified event.
 */
export function handleWebhookEvent(rawBody, signatureHeader) {
  const client = getClient();
  if (!client) throw new Error('Stripe is not configured (STRIPE_SECRET_KEY unset)');
  const event = client.webhooks.constructEvent(rawBody, signatureHeader, process.env.STRIPE_WEBHOOK_SECRET);
  const obj = event.data.object;

  if (event.type === 'checkout.session.completed') {
    recordSubscription({
      stripeSubscriptionId: obj.subscription,
      stripeCustomerId: obj.customer,
      email: obj.customer_details?.email ?? obj.customer_email ?? null,
      plan: 'team',
      status: 'active'
    });
    // There's no account/email system to tie this payment to a device-keyed org, so a
    // one-time code is the bridge: generated here, shown on the landing page's success
    // screen, and redeemed by the org owner in the app (see /orgs/:orgId/redeem-license).
    createLicenseCode({ stripeSubscriptionId: obj.subscription, stripeCustomerId: obj.customer });
  } else if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
    const status = event.type === 'customer.subscription.deleted' ? 'canceled' : obj.status;
    recordSubscription({
      stripeSubscriptionId: obj.id,
      stripeCustomerId: obj.customer,
      plan: 'team',
      status
    });
    // If this subscription's code was ever redeemed onto an org, keep that org's plan in
    // sync — otherwise a canceled/past-due subscription leaves the org permanently
    // "active" forever, since redemption is a one-time code, not a live foreign key.
    const licenseCode = getLicenseCodeBySubscription(obj.id);
    if (licenseCode?.org_id) {
      setOrgPlanStatus(licenseCode.org_id, status === 'active' ? 'active' : 'none');
    }
  }

  return event;
}
