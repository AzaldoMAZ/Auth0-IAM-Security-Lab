/**
 * Assigns a default Auth0 role after login when the user has no existing role.
 * Required Action secrets:
 * AUTH0_DOMAIN, CLIENT_ID, CLIENT_SECRET, DEFAULT_ROLE_ID
 */
exports.onExecutePostLogin = async (event, api) => {
  const currentRoles = event.authorization?.roles ?? [];

  if (currentRoles.length > 0) {
    return;
  }

  const { ManagementClient } = require("auth0");

  const management = new ManagementClient({
    domain: event.secrets.AUTH0_DOMAIN,
    clientId: event.secrets.CLIENT_ID,
    clientSecret: event.secrets.CLIENT_SECRET,
  });

  try {
    await management.users.roles.assign(event.user.user_id, {
      roles: [event.secrets.DEFAULT_ROLE_ID],
    });

    console.log(`Default role assigned to ${event.user.user_id}`);
  } catch (error) {
    console.log(`Failed to assign default role: ${error.message}`);
  }
};

