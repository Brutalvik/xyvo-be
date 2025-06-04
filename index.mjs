import awsLambdaFastify from "@fastify/aws-lambda";
import fastify from "fastify";
import fastifyCors from "@fastify/cors";
import dotenv from "dotenv";
import crypto from "crypto";

const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;

//Helpers
export function calculateSecretHash(username, clientId, clientSecret) {
  return crypto
    .createHmac("sha256", clientSecret)
    .update(username + clientId)
    .digest("base64");
}

dotenv.config();

const app = fastify({ logger: true });

// Allow CORS for local + deployed frontend
app.register(fastifyCors, {
  origin: ["http://localhost:3000", process.env.FRONTEND_URL_VERCEL],
  credentials: true,
});

// Allow parsing of JSON bodies
app.addContentTypeParser(
  "application/json",
  { parseAs: "string" },
  function (req, body, done) {
    try {
      const json = JSON.parse(body);
      done(null, json);
    } catch (err) {
      done(err);
    }
  }
);

// Register user in Cognito
app.post("/auth/register", async (req, reply) => {
  try {
    const { email, password, name } = req.body;

    const secretHash = calculateSecretHash(email, clientId, clientSecret);

    const response = await fetch(
      `https://cognito-idp.${process.env.REGION}.amazonaws.com/`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-amz-json-1.1",
          "X-Amz-Target": "AWSCognitoIdentityProviderService.SignUp",
          "X-Amz-User-Agent": "aws-amplify/3.0",
        },
        body: JSON.stringify({
          ClientId: clientId,
          SecretHash: secretHash,
          Username: email,
          Password: password,
          UserAttributes: [
            { Name: "email", Value: email },
            { Name: "name", Value: name },
          ],
        }),
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return reply
        .status(400)
        .send({ message: data.message || "Registration error" });
    }

    reply.send({ id: data.UserSub, email });
  } catch (error) {
    app.log.error("Registration failed", error);
    reply.status(500).send({ message: "Internal Server Error" });
  }
});

// Export for Lambda
export const handler = awsLambdaFastify(app);

// For local testing
if (process.env.NODE_ENV === "development") {
  app.listen({ port: 5000 }, (err) => {
    if (err) {
      console.error("Startup error:", err);
      process.exit(1);
    }
    console.log("Local API running on http://localhost:5000");
  });
}
