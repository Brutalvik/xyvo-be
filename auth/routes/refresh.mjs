import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";

/**
 * Registers the /auth/refresh route
 * @param {import('fastify').FastifyInstance} app
 */
export async function refreshTokenRoute(app) {
  app.post("/auth/refresh", async (req, reply) => {
    const cognitoRefreshToken = req.cookies.refreshToken;
    const jwtSecret = process.env.JWT_SECRET;
    const region = process.env.XYVO_REGION;
    const clientId = process.env.COGNITO_CLIENT_ID;
    const clientSecret = process.env.COGNITO_CLIENT_SECRET;

    if (!cognitoRefreshToken) {
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(401)
        .send({ message: "No refresh token provided. Please log in again." });
    }

    if (!clientSecret) {
      console.error("🔴 Missing COGNITO_CLIENT_SECRET env var");
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ message: "Server error: Client secret missing." });
    }

    try {
      const tokenEndpoint = `https://cognito-idp.${region}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/oauth2/token`;

      const requestBody = new URLSearchParams({
        grant_type: "refresh_token",
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: cognitoRefreshToken,
      });

      const response = await fetch(tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: requestBody.toString(),
      });

      const data = await response.json();

      if (!response.ok) {
        console.error("🔴 Cognito Refresh Error:", data);

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
          .send({ message: data.error_description || "Refresh failed." });
      }

      const { id_token, access_token, refresh_token } = data;

      if (!id_token || !access_token) {
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
          .send({ message: "Missing new tokens from Cognito" });
      }

      const userPayload = jwt.decode(id_token);

      const user = {
        id: userPayload.sub,
        email: userPayload.email,
      };

      const newJwtToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" });

      reply
        .setCookie(
          "token",
          newJwtToken,
          getCookieOptions({ includeMaxAge: true })
        )
        .setCookie("x-token", newJwtToken, {
          ...getCookieOptions({ includeMaxAge: true }),
          httpOnly: false,
        })
        .setCookie(
          "refreshToken",
          refresh_token || cognitoRefreshToken,
          getCookieOptions({
            includeMaxAge: true,
            maxAge: 30 * 24 * 60 * 60 * 1000,
            path: "/auth/refresh",
          })
        )
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(200)
        .send({ message: "Token refreshed", user });
    } catch (err) {
      console.error("🔴 Refresh error:", err);
      reply
        .clearCookie("token", getCookieOptions({ includeMaxAge: false }))
        .clearCookie("x-token", { path: "/" })
        .clearCookie(
          "refreshToken",
          getCookieOptions({ path: "/auth/refresh", includeMaxAge: false })
        )
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({
          error: "InternalServerError",
          message: "Unexpected error during token refresh. Please log in.",
        });
    }
  });
}
