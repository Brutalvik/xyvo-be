import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  GetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { query } from "../utils/db.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";

export async function refreshRoute(app) {
  const region = process.env.XYVO_REGION;
  const clientId = process.env.COGNITO_CLIENT_ID;
  const clientSecret = process.env.COGNITO_CLIENT_SECRET;
  const jwtSecret = process.env.JWT_SECRET;

  const cognitoClient = new CognitoIdentityProviderClient({ region });

  app.post("/auth/refresh", async (req, reply) => {
    const origin = req.headers.origin;
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken || typeof refreshToken !== "string") {
      return reply.status(401).send({ message: "Missing refresh token" });
    }

    const decoded = jwt.decode(refreshToken);
    const username = decoded?.sub;

    if (!username || !clientSecret) {
      return reply.status(401).send({
        message: "Invalid refresh token (sub missing or secret not set)",
      });
    }

    const secretHash = calculateSecretHash(username, clientId, clientSecret);

    try {
      const authResult = await cognitoClient.send(
        new InitiateAuthCommand({
          AuthFlow: "REFRESH_TOKEN_AUTH",
          ClientId: clientId,
          AuthParameters: {
            REFRESH_TOKEN: refreshToken,
            SECRET_HASH: secretHash,
          },
        })
      );

      const accessToken = authResult.AuthenticationResult?.AccessToken;
      if (!accessToken) {
        return reply.status(401).send({ message: "Invalid refresh token" });
      }

      const userData = await cognitoClient.send(
        new GetUserCommand({ AccessToken: accessToken })
      );

      const attrs = Object.fromEntries(
        (userData.UserAttributes || []).map(({ Name, Value }) => [Name, Value])
      );

      const fullName =
        attrs.name ||
        `${attrs.given_name || ""} ${attrs.family_name || ""}`.trim() ||
        attrs.email?.split("@")[0];

      const userId = attrs.sub;
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
        email: attrs.email,
        name: fullName,
        phone: attrs.phone_number || "",
        image: attrs.picture || "",
        organizationId,
        organizationName,
        timezone: attrs["custom:timezone"] || "UTC",
        role: attrs["custom:role"] || "individual",
        accountType: attrs["custom:accountType"] || "personal",
        socialIdp: null,
        createdAt: attrs["custom:created_at"] || null,
        lastLogin: attrs["custom:last_login"] || null,
        status: attrs["custom:status"] || "active",
        permissions,
        attributes: attrs,
      };

      const newJwt = jwt.sign(
        {
          id: user.id,
          sub: user.sub,
          email: user.email,
          name: user.name,
          organizationId: user.organizationId,
          role: user.role,
        },
        jwtSecret,
        { expiresIn: "1h" }
      );

      return reply
        .setCookie("token", newJwt, getCookieOptions({ includeMaxAge: true }))
        .setCookie("x-token", newJwt, {
          ...getCookieOptions({ includeMaxAge: true }),
          httpOnly: false,
        })
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ isLoggedIn: true, user });
    } catch (err) {
      console.error("Refresh token error:", err);
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(401)
        .send({ message: "Invalid refresh token" });
    }
  });
}
