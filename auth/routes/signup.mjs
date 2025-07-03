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

export async function signupRoute(app) {
  app.post("/auth/signup", async (req, reply) => {
    const region = process.env.XYVO_REGION;
    const clientId = process.env.COGNITO_CLIENT_ID;
    const clientSecret = process.env.COGNITO_CLIENT_SECRET;
    const jwtSecret = process.env.JWT_SECRET;
    const userPoolId = process.env.COGNITO_USER_POOL_ID;

    const cognitoClient = new CognitoIdentityProviderClient({ region });

    try {
      const { email, phone, password, name, usageType, timezone } = req.body;

      if (!email || !password || !name) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({
            message: "Name, email, and password are required",
          });
      }

      if (!usageType) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(202)
          .send({
            message:
              "Please confirm if this account is for personal or team use.",
            requireUsageType: true,
          });
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
          {
            Name: "phone_number",
            Value: phone.startsWith("+") ? phone : `+${phone}`,
          },
          { Name: "custom:account_type", Value: usageType },
          { Name: "custom:timezone", Value: timezone || "UTC" },
          {
            Name: "custom:role",
            Value: usageType === "team" ? "owner" : "individual",
          },
          {
            Name: "custom:organization_id",
            Value: usageType === "team" ? "pending" : "",
          },
        ],
      });

      await cognitoClient.send(signUpCommand);

      const confirmCommand = new AdminConfirmSignUpCommand({
        UserPoolId: userPoolId,
        Username: email,
      });

      await cognitoClient.send(confirmCommand);

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
          .clearCookie("x-token", { path: "/" })
          .clearCookie(
            "refreshToken",
            getCookieOptions({ path: "/auth/refresh", includeMaxAge: false })
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
        sub: attributes.sub,
        email: attributes.email,
        name: attributes.name || attributes.given_name,
        phone: attributes.phone_number || null,
        accountType: attributes["custom:accountType"],
        organizationId: attributes["custom:organizationId"] || null,
        timezone: attributes["custom:timezone"] || "UTC",
        role: attributes["custom:role"] || "individual",
        attributes,
      };

      const jwtToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" });

      reply
        .setCookie("token", jwtToken, getCookieOptions({ includeMaxAge: true }))
        .setCookie("x-token", jwtToken, {
          path: "/",
          sameSite: "Strict",
          maxAge: 60 * 60,
        })
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
        .header("Access-Control-Allow-Methods", "POST, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
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
