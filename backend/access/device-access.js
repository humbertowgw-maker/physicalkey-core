export function checkPermission(deviceId, action, userRole = 'developer') {
  const roles = {
    admin: ['read', 'write', 'delete', 'admin'],
    developer: ['read', 'write'],
    guest: ['read']
  };

  const permissions = roles[userRole] || roles.guest;
  return permissions.includes(action);
}

export function getDeviceAccessLevel(deviceId, subscription = 'free') {
  const tiers = {
    free: { devices: 1, apiCalls: 100 },
    pro: { devices: 5, apiCalls: 10000 },
    enterprise: { devices: 100, apiCalls: 1000000 }
  };

  const tier = tiers[subscription] || tiers.free;
  return {
    deviceId,
    subscription,
    ...tier,
    timestamp: new Date().toISOString()
  };
}
