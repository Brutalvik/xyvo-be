import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import { query } from "../utils/db.mjs";

export async function meRoute(app) {
  const region = process.env.XYVO_REGION;
  const userPoolId = process.env.COGNITO_USER_POOL_ID;
  const jwtSecret = process.env.JWT_SECRET;
  const cognitoClient = new CognitoIdentityProviderClient({ region });

  app.get("/auth/me", async (req, reply) => {
    const origin = req.headers.origin;
    const authHeader = req.headers["authorization"];
    const cookieToken = req.cookies?.token;
    const bearerToken = authHeader?.startsWith("Bearer ")
      ? authHeader.slice(7)
      : null;
    const token = cookieToken || bearerToken;

    if (!token) {
      return reply
        .code(401)
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ isLoggedIn: false, message: "Not authenticated" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, jwtSecret);
    } catch (err) {
      return reply
        .code(401)
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ isLoggedIn: false, message: "Invalid or expired token" });
    }

    try {
      const userDetails = await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: userPoolId,
          Username: decoded.sub,
        })
      );

      const attrs = Object.fromEntries(
        (userDetails.UserAttributes || []).map(({ Name, Value }) => [
          Name,
          Value,
        ])
      );

      const fullName =
        attrs.name ||
        `${attrs.given_name || ""} ${attrs.family_name || ""}`.trim() ||
        decoded.email?.split("@")[0];

      const userId = attrs.sub || decoded.sub;
      const organizationId =
        attrs["custom:organizationId"] ||
        attrs["custom:organization_id"] ||
        null;

      const permissionsRes = await query(
        "SELECT permission FROM user_permissions WHERE user_id = $1",
        [userId]
      );
      const permissions = permissionsRes.rows.map((r) => r.permission);

      let organizationName = null;
      if (organizationId) {
        const orgRes = await query(
          "SELECT name FROM organizations WHERE id = $1",
          [organizationId]
        );
        organizationName = orgRes.rows[0]?.name || null;
      }

      const user = {
        id: userId,
        sub: userId,
        email: attrs.email || decoded.email,
        name: fullName,
        phone: attrs.phone_number || "",
        image: attrs.picture || "",
        organizationId,
        organizationName,
        timezone: attrs["custom:timezone"] || "UTC",
        role: attrs["custom:role"] || "individual",
        accountType: attrs["custom:accountType"] || "personal",
        socialIdp: decoded.socialIdp || null,
        createdAt: attrs["custom:created_at"] || null,
        lastLogin: attrs["custom:last_login"] || null,
        status: attrs["custom:status"] || "active",
        permissions,
        attributes: attrs,
      };

      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ isLoggedIn: true, user });
    } catch (err) {
      console.error("AdminGetUser error:", err);
      return reply
        .code(500)
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({
          isLoggedIn: false,
          message: "Failed to fetch user",
          error: err.message,
        });
    }
  });
}
