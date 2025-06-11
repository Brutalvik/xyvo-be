import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  GetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";

export async function signinRoutes(app) {
  app.post("/auth/signin", async (req, reply) => {
    const region = process.env.XYVO_REGION;
    const jwtSecret = process.env.JWT_SECRET;

    const cognitoClient = new CognitoIdentityProviderClient({ region });

    try {
      const { email, password, userPoolId } = req.body || {};

      if (!email || !password || !userPoolId) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ error: "Email, password, and userPoolId are required" });
      }

      let clientId;
      let clientSecret;

      if (userPoolId === process.env.COGNITO_USER_POOL_ID) {
        clientId = process.env.COGNITO_CLIENT_ID;
        clientSecret = process.env.COGNITO_CLIENT_SECRET;
      } else if (userPoolId === process.env.COGNITO_SELLER_POOL_ID) {
        clientId = process.env.COGNITO_CLIENT_ID_SELLERS;
        clientSecret = process.env.COGNITO_CLIENT_SECRET_SELLERS;
      } else {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ error: "Invalid userPoolId provided" });
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
        UserPoolId: userPoolId,
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
        sub: attributes.sub, // ADDED: Ensures the JWT payload has a 'sub' claim
        email: attributes.email,
        name: attributes.name || attributes.given_name,
        phone: attributes.phone_number || null,
        given_name: attributes.given_name,
        family_name: attributes.family_name,
        business_name: attributes["custom:business_name"],
        group:
          userPoolId === process.env.COGNITO_SELLER_POOL_ID
            ? "Sellers"
            : "Customers",
      };

      const jwtToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" });

      reply
        .setCookie("token", jwtToken, getCookieOptions({ includeMaxAge: true }))
        .setCookie(
          "refreshToken",
          refreshToken,
          getCookieOptions({
            includeMaxAge: true,
            maxAge: 30 * 24 * 60 * 60 * 1000,
            path: "/auth/refresh",
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
