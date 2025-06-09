import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";

/**
 * Registers the /auth/checkuser route
 * @param {import('fastify').FastifyInstance} app
 */
export async function checkUserRoutes(app) {
  app.post("/auth/checkuser", async (req, reply) => {
    const { email } = req.body;

    if (!email) {
      return reply.status(400).send({ error: "Email is required" });
    }

    const region = process.env.XYVO_REGION;
    const userPoolId = process.env.COGNITO_USER_POOL_ID;

    const cognitoClient = new CognitoIdentityProviderClient({ region });

    try {
      const command = new AdminGetUserCommand({
        UserPoolId: userPoolId,
        Username: email,
      });

      await cognitoClient.send(command);

      reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ exists: true });
    } catch (err) {
      console.error("🔴 Cognito error:", err);
      reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ exists: false });
    }
  });
}
