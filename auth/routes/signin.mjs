import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  AdminGetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";
import { query } from "../utils/db.mjs";

// ✅ Move static configs outside to avoid recomputing for each request
const region = process.env.XYVO_REGION;
const jwtSecret = process.env.JWT_SECRET;
const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;
const userPoolId = process.env.COGNITO_USER_POOL_ID;

const cognitoClient = new CognitoIdentityProviderClient({ region });

export async function signinRoute(app) {
  app.post("/auth/signin", async (req, reply) => {
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

      // ✅ Authenticate with Cognito
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
      const {
        IdToken: idToken,
        AccessToken: accessToken,
        RefreshToken: refreshToken,
        ExpiresIn: expiresIn,
      } = authResponse.AuthenticationResult || {};

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

      // ✅ Fetch user details from Cognito
      const userDetails = await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: userPoolId,
          Username: email,
        })
      );

      console.log("User details fetched:", userDetails.UserStatus);

      // ✅ Build attributes object efficiently (O(n), no extra allocations)
      const attrs = {};
      for (const { Name, Value } of userDetails.UserAttributes || []) {
        attrs[Name] = Value;
      }

      const userId = attrs.sub;
      const fullName =
        attrs.name ||
        `${attrs.given_name || ""} ${attrs.family_name || ""}`.trim() ||
        email.split("@")[0];
      const organizationId =
        attrs["custom:organizationId"] ||
        attrs["custom:organization_id"] ||
        null;

      // ✅ Run DB queries in parallel
      const [permissionsRes, orgRes] = await Promise.all([
        query("SELECT permission FROM user_permissions WHERE user_id = $1", [
          userId,
        ]),
        organizationId
          ? query("SELECT name FROM organizations WHERE id = $1", [
              organizationId,
            ])
          : Promise.resolve({ rows: [] }),
      ]);

      const permissions = permissionsRes.rows.map((r) => r.permission);
      const organizationName = orgRes.rows[0]?.name || null;

      // ✅ Construct user object
      const user = {
        id: userId,
        email: attrs.email || email,
        name: fullName,
        phone: attrs.phone_number || "",
        image: attrs.picture || "",
        organizationId,
        organizationName,
        timezone: attrs["custom:timezone"] || "UTC",
        role: attrs["custom:role"] || "individual",
        accountType: attrs["custom:accountType"] || "personal",
        status: attrs["custom:status"] || "active",
        permissions,
        confirmedUser: userDetails.UserStatus,
      };

      // ✅ Generate JWT
      const jwtToken = jwt.sign(
        {
          id: user.id,
          email: user.email,
          name: user.name,
          organizationId: user.organizationId,
          role: user.role,
          exp: Math.floor(Date.now() / 1000) + expiresIn,
        },
        jwtSecret
      );

      // ✅ Set cookies and return response
      reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
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
            maxAge: 30 * 24 * 60 * 60,
            path: "/auth/refresh",
          })
        )
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
