// routes/verifyCode.mjs
import {
  CognitoIdentityProviderClient,
  ConfirmSignUpCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { calculateSecretHash } from "../utils/helpers.mjs";

const client = new CognitoIdentityProviderClient({
  region: process.env.AWS_REGION,
});

const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;

/**
 * Registers the /auth/verify-code route
 * @param {import('fastify').FastifyInstance} app
 */

export async function verifyCodeRoute(app) {
  app.post("/auth/verify-code", async (req, reply) => {
    try {
      const { email, code } = req.body;

      if (!email || !code) {
        return reply.status(400).send({ error: "Email and code are required." });
      }

      const secretHash = calculateSecretHash(email, clientId, clientSecret);

      const command = new ConfirmSignUpCommand({
        ClientId: clientId,
        Username: email,
        ConfirmationCode: code,
        SecretHash: secretHash,
      });

      await client.send(command);

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(200)
        .send({ message: "Email verified successfully." });
    } catch (err) {
      console.error(err);
      return reply
        .status(500)
        .send({ error: err.message || "Failed to verify code." });
    }
  });
}
