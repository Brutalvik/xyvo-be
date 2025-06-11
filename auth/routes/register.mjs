import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";
import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  AdminConfirmSignUpCommand,
  InitiateAuthCommand,
  GetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";

export async function registerRoutes(app) {
  app.post("/auth/register", async (req, reply) => {
    const region = process.env.XYVO_REGION;
    const clientId = process.env.COGNITO_CLIENT_ID;
    const clientSecret = process.env.COGNITO_CLIENT_SECRET;
    const jwtSecret = process.env.JWT_SECRET;
    const userPoolId = process.env.COGNITO_USER_POOL_ID;

    const cognitoClient = new CognitoIdentityProviderClient({ region });

    try {
      const { email, phone, password, name } = req.body;

      if (!email || !password || !name) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ message: "Email, password, and name are required" });
      }

      const secretHash = calculateSecretHash(email, clientId, clientSecret);

      const signUpCommand = new SignUpCommand({
        ClientId: clientId,
        Username: email,
        Password: password,
        SecretHash: secretHash,
        UserAttributes: [
          { Name: "email", Value: email },
          { Name: "name", Value: name },
          { Name: "given_name", Value: name },
          { Name: "phone_number", Value: phone },
        ],
      });
      const signUpResult = await cognitoClient.send(signUpCommand);

      const adminConfirmSignUpCommand = new AdminConfirmSignUpCommand({
        UserPoolId: userPoolId,
        Username: email,
      });
      await cognitoClient.send(adminConfirmSignUpCommand);

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
        .status(201)
        .send({ user, isRegistered: true, isLoggedIn: true });
    } catch (error) {
      console.error("Registration failed:", error);

      if (error.name === "UsernameExistsException") {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(409)
          .send({ message: "Email already registered." });
      } else if (error.name === "InvalidPasswordException") {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ message: "Password does not meet requirements." });
      } else if (error.name === "UserNotConfirmedException") {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({
            message: "User not confirmed. Please check your email/phone.",
          });
      }

      reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ message: "Internal Server Error" });
    }
  });
}
