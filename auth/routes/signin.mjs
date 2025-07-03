import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  GetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";

export async function signinRoute(app) {
  app.post("/auth/signin", async (req, reply) => {
    const region = process.env.XYVO_REGION;
    const jwtSecret = process.env.JWT_SECRET;
    const clientId = process.env.COGNITO_CLIENT_ID;
    const clientSecret = process.env.COGNITO_CLIENT_SECRET;
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
      const expiresIn = authResponse.AuthenticationResult?.ExpiresIn;

      if (!idToken || !accessToken || !refreshToken) {
        return reply
          .clearCookie("token", getCookieOptions({ includeMaxAge: false }))
          .clearCookie("x-token", { path: "/" })
          .clearCookie(
            "refreshToken",
            getCookieOptions({ path: "/auth/refresh", includeMaxAge: false })
          )
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(401)
          .send({ error: "Authentication failed: Missing tokens." });
      }

      // Fetch minimal user info to sign into JWT
      const getUserCommand = new GetUserCommand({ AccessToken: accessToken });
      const userData = await cognitoClient.send(getUserCommand);
      const attributes = {};
      userData.UserAttributes.forEach((attr) => {
        attributes[attr.Name] = attr.Value;
      });

      const userJwtPayload = {
        id: attributes.sub,
        sub: attributes.sub,
        email: attributes.email,
        name:
          attributes.name ||
          `${attributes.given_name || ""} ${
            attributes.family_name || ""
          }`.trim() ||
          email.split("@")[0],
        phone: attributes.phone_number || "",
        organizationId: attributes["custom:organization_id"] || null,
        role: attributes["custom:role"] || "individual",
        accessTokenExpiresAt: Math.floor(Date.now() / 1000) + expiresIn,
      };

      const jwtToken = jwt.sign(userJwtPayload, jwtSecret, {
        expiresIn: "1h",
      });

      reply
        .setCookie("token", jwtToken, getCookieOptions({ includeMaxAge: true }))
        .setCookie("x-token", jwtToken, {
          ...getCookieOptions({ includeMaxAge: true }),
          httpOnly: false,
        })
        .setCookie(
          "refreshToken",
          refreshToken,
          getCookieOptions({
            includeMaxAge: true,
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            path: "/auth/refresh",
          })
        )
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({
          message: "Login successful",
          isLoggedIn: true,
        });
    } catch (err) {
      console.error("Cognito signin error:", err);
      req.log.error("Cognito signin error:", err?.name || err);

      let errorMessage = "Authentication failed";
      let statusCode = 500;

      if (
        err.name === "NotAuthorizedException" ||
        err.name === "UserNotFoundException" ||
        err.name === "UserNotConfirmedException"
      ) {
        errorMessage = err.message;
        statusCode = 401;
      }

      reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(statusCode)
        .send({
          error: err.name || "SigninError",
          message: errorMessage,
        });
    }
  });
}
