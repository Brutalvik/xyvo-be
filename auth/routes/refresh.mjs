// routes/refresh.mjs
import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";

export async function refreshRoute(app) {
  const region = process.env.XYVO_REGION;
  const userPoolId = process.env.COGNITO_USER_POOL_ID;
  const jwtSecret = process.env.JWT_SECRET;
  const cognitoClient = new CognitoIdentityProviderClient({ region });

  app.post("/auth/refresh", async (req, reply) => {
    const origin = req.headers.origin;
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(401)
        .send({ message: "Refresh token missing" });
    }

    try {
      const decoded = jwt.verify(refreshToken, jwtSecret);

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
        decoded.email.split("@")[0];

      const user = {
        id: decoded.sub,
        email: attrs.email || decoded.email,
        name: fullName,
        phone: attrs.phone_number,
        sub: decoded.sub,
        socialIdp: decoded.socialIdp || null,
        organizationId: attrs["custom:organization_id"] || null,
        role: attrs["custom:role"] || "individual",
      };

      const newAccessToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" });

      return reply
        .setCookie(
          "token",
          newAccessToken,
          getCookieOptions({ includeMaxAge: true })
        )
        .setCookie("x-token", newAccessToken, {
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
