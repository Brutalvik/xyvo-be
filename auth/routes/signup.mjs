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
import { v4 as uuidv4 } from "uuid";
import { query } from "../utils/db.mjs";

export async function signupRoute(app) {
  app.post("/auth/signup", async (req, reply) => {
    const region = process.env.XYVO_REGION;
    const clientId = process.env.COGNITO_CLIENT_ID;
    const clientSecret = process.env.COGNITO_CLIENT_SECRET;
    const jwtSecret = process.env.JWT_SECRET;
    const userPoolId = process.env.COGNITO_USER_POOL_ID;

    const cognitoClient = new CognitoIdentityProviderClient({ region });

    try {
      const { email, phone, password, name, usageType, timezone, plan } =
        req.body;

      if (!email || !password || !name) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ message: "Name, email, and password are required" });
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
      const organizationId = uuidv4();

      const orgName =
        usageType === "team"
          ? `${name}'s Organization`
          : `${name}'s Personal Org`;

      // Insert organization
      await query(
        `INSERT INTO organizations (id, name, plan) VALUES ($1, $2, $3)`,
        [organizationId, orgName, plan || "free"]
      );

      // Sign up in Cognito
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
            Value: phone?.startsWith("+") ? phone : `+${phone}`,
          },
          { Name: "custom:account_type", Value: usageType },
          { Name: "custom:timezone", Value: timezone || "UTC" },
          { Name: "custom:plan", Value: plan || "free" },
          {
            Name: "custom:role",
            Value: usageType === "team" ? "owner" : "individual",
          },
          { Name: "custom:organization_id", Value: organizationId },
        ],
      });

      await cognitoClient.send(signUpCommand);

      // Auto-confirm user
      await cognitoClient.send(
        new AdminConfirmSignUpCommand({
          UserPoolId: userPoolId,
          Username: email,
        })
      );

      // Sign in the user
      const authResponse = await cognitoClient.send(
        new InitiateAuthCommand({
          AuthFlow: "USER_PASSWORD_AUTH",
          ClientId: clientId,
          AuthParameters: {
            USERNAME: email,
            PASSWORD: password,
            SECRET_HASH: secretHash,
          },
        })
      );

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

      // Get user info from Cognito
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
        accountType: attributes["custom:account_type"],
        organizationId: attributes["custom:organization_id"] || null,
        timezone: attributes["custom:timezone"] || "UTC",
        role: attributes["custom:role"] || "individual",
        plan: attributes["custom:plan"] || "free",
        attributes,
      };

      // UPSERT user into DB
      await query(
        `
        INSERT INTO users (
          id, sub, email, name, phone,
          image, role, account_type,
          organization_id, timezone, plan,
          created_at, updated_at
        ) VALUES (
          $1, $2, $3, $4, $5,
          $6, $7, $8,
          $9, $10, $11,
          NOW(), NOW()
        )
        ON CONFLICT (email) DO UPDATE SET
          sub = EXCLUDED.sub,
          name = EXCLUDED.name,
          phone = EXCLUDED.phone,
          role = EXCLUDED.role,
          account_type = EXCLUDED.account_type,
          organization_id = EXCLUDED.organization_id,
          timezone = EXCLUDED.timezone,
          plan = EXCLUDED.plan,
          updated_at = NOW();
        `,
        [
          user.id,
          user.sub,
          user.email,
          user.name,
          user.phone,
          "", // image
          user.role,
          user.accountType,
          user.organizationId,
          user.timezone,
          user.plan,
        ]
      );

      // Generate JWT
      const jwtToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" });

      // Send cookies and response
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

      const headers = {
        "Access-Control-Allow-Origin": req.headers.origin,
        "Access-Control-Allow-Credentials": "true",
      };

      if (error.name === "UsernameExistsException") {
        return reply.headers(headers).status(409).send({
          message: "Email already registered in Cognito.",
        });
      }

      if (error.name === "InvalidPasswordException") {
        return reply.headers(headers).status(400).send({
          message: "Password does not meet requirements.",
        });
      }

      if (error.name === "UserNotConfirmedException") {
        return reply.headers(headers).status(400).send({
          message: "User not confirmed. Please check your email/phone.",
        });
      }

      return reply.headers(headers).status(500).send({
        message: "Internal Server Error",
      });
    }
  });
}
