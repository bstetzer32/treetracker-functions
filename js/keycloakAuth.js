/**
 * Keycloak authentication helper for Knative/faas-js-runtime functions.
 *
 * Usage in a Knative function:
 *   const { verifyKeycloakToken } = require('./keycloakAuth');
 *
 *   const handle = async (context, body) => {
 *     const user = await verifyKeycloakToken(context);
 *     if (!user) return { statusCode: 401, statusMessage: 'Unauthorized' };
 *     // ... proceed with authenticated logic
 *   };
 */

const KEYCLOAK_BASE_URL = process.env.PRIVATE_KEYCLOAK_BASE_URL || '';
const KEYCLOAK_REALM = process.env.PRIVATE_KEYCLOAK_REALM || 'treetracker';

/**
 * Verify a Keycloak Bearer token from a Knative function context.
 * Returns the user info payload on success, or null if unauthenticated.
 */
async function verifyKeycloakToken(context) {
  if (!KEYCLOAK_BASE_URL) return null;

  const auth = context.headers?.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;

  const token = auth.slice(7);
  const userinfoUrl = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/userinfo`;

  try {
    const response = await fetch(userinfoUrl, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

module.exports = { verifyKeycloakToken };
