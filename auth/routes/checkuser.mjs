import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";

const userPoolId = process.env.COGNITO_USER_POOL_ID;
const region = process.env.REGION;

const cognitoClient = new CognitoIdentityProviderClient({ region });

/**
 * Registers the /auth/checkuser route
 * @param {import('fastify').FastifyInstance} app
 */
export async function checkUserRoutes(app) {
  // ✅ CORS Preflight Handler
  app.options("/auth/checkuser", async (req, reply) => {
    reply
      .header("Access-Control-Allow-Origin", req.headers.origin || "*")
      .header("Access-Control-Allow-Methods", "POST, OPTIONS")
      .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
      .header("Access-Control-Allow-Credentials", "true")
      .code(204)
      .send();
  });

  // ✅ POST Route to Check if User Exists
  app.post("/auth/checkuser", async (req, reply) => {
    const { email } = req.body;

    if (!email) {
      return reply.status(400).send({ error: "Email is required" });
    }

    try {
      const command = new AdminGetUserCommand({
        UserPoolId: userPoolId,
        Username: email,
      });

      await cognitoClient.send(command);

      // ✅ User exists
      reply
        .header("Access-Control-Allow-Origin", req.headers.origin || "*")
        .header("Access-Control-Allow-Credentials", "true")
        .send({ exists: true });
    } catch (err) {
      // ✅ User does not exist or error occurred
      req.log.warn("User not found or Cognito error:", err?.name || err);

      reply
        .header("Access-Control-Allow-Origin", req.headers.origin || "*")
        .header("Access-Control-Allow-Credentials", "true")
        .send({ exists: false });
    }
  });
}
