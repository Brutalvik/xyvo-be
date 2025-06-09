// routes/signin.mjs
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  GetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";

/**
 * Registers the /auth/signin route
 * @param {import('fastify').FastifyInstance} app
 */
export async function signinRoutes(app) {
  // ✅ Main POST /auth/signin route
  app.post("/auth/signin", async (req, reply) => {
    const region = process.env.XYVO_REGION;
    const clientId = process.env.COGNITO_CLIENT_ID;
    const clientSecret = process.env.COGNITO_CLIENT_SECRET;
    const jwtSecret = process.env.JWT_SECRET;

    const cognitoClient = new CognitoIdentityProviderClient({ region });

    try {
      const { email, password } = req.body || {};

      if (!email || !password) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
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
      const refreshToken = authResponse.AuthenticationResult?.RefreshToken;

      if (!idToken || !accessToken || !refreshToken) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(401)
          .send({ error: "Authentication failed: Missing tokens." });
      }

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

      const jwtToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" }); //custom short-lived JWT

      reply
        .setCookie("token", jwtToken, getCookieOptions({ includeMaxAge: true }))
        .setCookie(
          "refreshToken",
          refreshToken,
          getCookieOptions({
            includeMaxAge: true,
            maxAge: 30 * 24 * 60 * 60 * 1000, // Cognito setting (30 days)
            path: "/auth/refresh", // IMPORTANT: Only send this cookie to the refresh endpoint
          })
        )
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({
          message: "Login successful",
          isLoggedIn: true,
          user,
        });
    } catch (err) {
      console.error("🔴 Cognito signin error:", err);
      req.log.error("Cognito signin error:", err?.name || err);

      reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({
          error: err.name || "SigninError",
          message: err.message || "Authentication failed",
        });
    }
  });
}
