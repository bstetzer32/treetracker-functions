/**
 * Keycloak authentication helper for Knative/faas-js-runtime functions.
 *
 * Knative functions receive a `context` object (not Express req/res), so this
 * module provides a standalone token verification function that reads the
 * Authorization header from `context.headers`.
 *
 * Usage in a Knative function:
 *   const { verifyKeycloakToken } = require('./keycloakAuth');
 *
 *   const handle = async (context, body) => {
 *     const user = await verifyKeycloakToken(context);
 *     if (!user) return { statusCode: 401, statusMessage: 'Unauthorized' };
 *     // ... proceed with authenticated logic
 *   };
 *
 * Dev-mode bypass: Returns null (unauthenticated) if PRIVATE_KEYCLOAK_BASE_URL
 * is not configured, allowing local development without Keycloak.
 */

// Read Keycloak connection settings from environment
const KEYCLOAK_BASE_URL = process.env.PRIVATE_KEYCLOAK_BASE_URL || '';
const KEYCLOAK_REALM = process.env.PRIVATE_KEYCLOAK_REALM || 'treetracker';

/**
 * Verify a Keycloak Bearer token from a Knative function context.
 * Calls Keycloak's userinfo endpoint to validate the token (online strategy).
 *
 * @param {object} context - Knative function context with `.headers` property
 * @returns {Promise<object|null>} User info payload on success, or null if unauthenticated/invalid
 */
async function verifyKeycloakToken(context) {
  // Skip verification if Keycloak is not configured (dev mode)
  if (!KEYCLOAK_BASE_URL) return null;

  // Extract Bearer token from the Authorization header
  const auth = context.headers?.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;

  const token = auth.slice(7);
  // Validate token by calling Keycloak's userinfo endpoint
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
