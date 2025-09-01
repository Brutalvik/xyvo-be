// routes/resendVerification.mjs
import { CognitoIdentityProviderClient, ResendConfirmationCodeCommand } from "@aws-sdk/client-cognito-identity-provider";
import { calculateSecretHash } from "../utils/helpers.mjs";
const client = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION });

/**
 * Registers the /auth/resend-verification route
 * @param {import('fastify').FastifyInstance} app
 */

const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;

export async function resendVerificationRoute(app) {
  app.post("/auth/resend-verification", async (req, reply) => {
    try {
      const { email } = req.body;

      if (!email) {
        return reply.status(400).send({ error: "Email is required." });
      }

      const secretHash = calculateSecretHash(email, clientId, clientSecret);

      const command = new ResendConfirmationCodeCommand({
        ClientId: clientId,
        Username: email,
        SecretHash: secretHash,
      });

      await client.send(command);

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(200)
        .send({ message: "Verification code resent successfully." });
    } catch (err) {
      console.error(err);
      return reply.status(500).send({ error: err.message || "Failed to resend code." });
    }
  });
}
