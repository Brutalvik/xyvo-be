// routes/signin.mjs
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  GetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";

const region = process.env.REGION;
const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;
const jwtSecret = process.env.JWT_SECRET;

const cognitoClient = new CognitoIdentityProviderClient({ region });

/**
 * Registers the /auth/signin route
 * @param {import('fastify').FastifyInstance} app
 */
export async function signinRoutes(app) {
  // ✅ Manual CORS preflight handler - You can likely remove or comment this out
  //    once API Gateway handles the OPTIONS request directly.
  // app.options("/auth/signin", async (req, reply) => {
  //   console.log("OPTIONS /auth/signin hit");
  //   reply
  //     .header("Access-Control-Allow-Origin", req.headers.origin || "*")
  //     .header("Access-Control-Allow-Methods", "POST, OPTIONS")
  //     .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
  //     .header("Access-Control-Allow-Credentials", "true")
  //     .code(204)
  //     .send();
  // });

  // ✅ Main POST /auth/signin route
  app.post("/auth/signin", async (req, reply) => {
    try {
      // Safely extract credentials
      const { email, password } = req.body || {};

      if (!email || !password) {
        // Fastify-cors should handle these headers, but explicitly adding them
        // provides an extra layer of certainty for error responses.
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin || "*")
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ error: "Email and password are required" });
      }

      const secretHash = calculateSecretHash(email, clientId, clientSecret);

      const authCommand = new InitiateAuthCommand({
        AuthFlow: "USER_PASSWORD_AUTH",
        ClientId: clientId,
        AuthParameters: {
          USERNAME: email,
          PASSWORD: password,
          SECRET_HASH: secretHash,
        },
      });

      const authResponse = await cognitoClient.send(authCommand);
      const idToken = authResponse.AuthenticationResult?.IdToken;
      const accessToken = authResponse.AuthenticationResult?.AccessToken;

      if (!idToken || !accessToken) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin || "*")
          .header("Access-Control-Allow-Credentials", "true")
          .status(401)
          .send({ error: "Authentication failed" });
      }

      // ✅ Get user profile
      const getUserCommand = new GetUserCommand({ AccessToken: accessToken });
      const userData = await cognitoClient.send(getUserCommand);

      const attributes = {};
      userData.UserAttributes.forEach((attr) => {
        attributes[attr.Name] = attr.Value;
      });

      const user = {
        id: attributes.sub,
        email: attributes.email,
        name: attributes.name || attributes.given_name,
        phone: attributes.phone_number || null,
      };

      const jwtToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" });

      reply
        .setCookie("token", jwtToken, getCookieOptions({ includeMaxAge: true }))
        // Fastify-cors will typically add these, but ensuring consistency.
        .header("Access-Control-Allow-Origin", req.headers.origin || "*")
        .header("Access-Control-Allow-Credentials", "true")
        .send({
          message: "Login successful",
          isLoggedIn: true,
          user,
        });
    } catch (err) {
      req.log.error("Cognito signin error:", err);

      reply
        // Fastify-cors will typically add these, but ensuring consistency for error responses.
        .header("Access-Control-Allow-Origin", req.headers.origin || "*")
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({
          error: err.name || "SigninError",
          message: err.message || "Authentication failed",
        });
    }
  });
}
