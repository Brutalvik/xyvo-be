// routes/register.mjs
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand, // for post-registration login
  GetUserCommand, // for post-registration login to get user details
} from "@aws-sdk/client-cognito-identity-provider";

/**
 * Registers the /auth/register route
 * @param {import('fastify').FastifyInstance} app
 */
export async function registerRoutes(app) {
  // ✅ Register POST handler
  app.post("/auth/register", async (req, reply) => {
    const region = process.env.XYVO_REGION;
    const clientId = process.env.COGNITO_CLIENT_ID;
    const clientSecret = process.env.COGNITO_CLIENT_SECRET;
    const jwtSecret = process.env.JWT_SECRET;

    const cognitoClient = new CognitoIdentityProviderClient({ region });

    try {
      const { email, phone, password, name } = req.body;

      if (!email || !password || !name) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ error: "Email, password, and name are required" });
      }

      const secretHash = calculateSecretHash(email, clientId, clientSecret);

      // --- Step 1: Sign Up the User ---
      const signUpResponse = await fetch(
        `https://cognito-idp.${region}.amazonaws.com/`,
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
              { Name: "given_name", Value: name },
              { Name: "phone_number", Value: phone },
            ],
          }),
        }
      );

      const signUpData = await signUpResponse.json();

      if (!signUpResponse.ok) {
        console.error("🔴 Cognito SignUp Error:", signUpData);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ message: signUpData.message || "Registration error" });
      }

      // --- Step 2: Auto-Login the User (InitiateAuth) to get tokens ---
      // This assumes auto-confirmation is enabled in Cognito, or that
      // confirmation happens out-of-band and the user is ready to sign in.
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
      const refreshToken = authResponse.AuthenticationResult?.RefreshToken; // REFRESH TOKEN

      if (!idToken || !accessToken || !refreshToken) {
        console.error(
          "🔴 Auto-login failed after registration: Missing tokens."
        );
        // clean state
        reply
          .clearCookie("token", getCookieOptions({ includeMaxAge: false }))
          .clearCookie(
            "refreshToken",
            getCookieOptions({ includeMaxAge: false, path: "/auth/refresh" })
          );
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({
            message:
              "Registration successful, but auto-login failed. Please try signing in.",
          });
      }

      // --- Step 3: Get User Details and Create Custom JWT ---
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

      const jwtToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" }); // custom short-lived JWT

      // --- Step 4: Set Cookies and Send Response ---
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
        .status(201) // 201 Created is appropriate for successful registration followed by auto-login
        .send({ user, isRegistered: true, isLoggedIn: true });
    } catch (error) {
      console.error("🔴 Registration failed:", error);
      req.log.error("Registration failed:", error?.name || error);

      reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ message: "Internal Server Error" });
    }
  });
}
