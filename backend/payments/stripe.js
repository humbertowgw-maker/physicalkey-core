import Stripe from 'stripe';
import { recordSubscription } from './subscriptions.js';

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
  } else if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
    recordSubscription({
      stripeSubscriptionId: obj.id,
      stripeCustomerId: obj.customer,
      plan: 'team',
      status: event.type === 'customer.subscription.deleted' ? 'canceled' : obj.status
    });
  }

  return event;
}
