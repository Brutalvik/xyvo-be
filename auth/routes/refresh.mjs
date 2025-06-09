// routes/refresh.mjs
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
// import { calculateSecretHash } from "../utils/helpers.mjs";

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
      //check for client secret if it's a confidential app
      console.error(
        "🔴 Missing COGNITO_CLIENT_SECRET environment variable for confidential client."
      );
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({
          message: "Server configuration error: Client secret missing.",
        });
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
        console.error("🔴 Cognito OAuth2 Token Refresh Error:", data);
        let errorMessage =
          data.error_description || data.error || "Failed to refresh token.";
        if (data.error === "invalid_grant") {
          errorMessage = "Session invalid. Please log in again.";
        } else if (data.error === "invalid_token") {
          errorMessage = "Session expired or invalid. Please log in again.";
        } else if (data.error === "unauthorized_client") {
          errorMessage =
            "Authentication failed: Invalid client or client secret.";
        }

        return reply
          .clearCookie("token", getCookieOptions({ includeMaxAge: false }))
          .clearCookie(
            "refreshToken",
            getCookieOptions({ includeMaxAge: false, path: "/auth/refresh" })
          )
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(401)
          .send({ message: errorMessage });
      }

      const newIdToken = data.id_token;
      const newAccessToken = data.access_token;
      const newCognitoRefreshToken = data.refresh_token; // Will be present if refresh token rotation is enabled

      if (!newIdToken || !newAccessToken) {
        console.error(
          "🔴 Cognito refresh did not return required tokens despite success status."
        );
        return reply
          .clearCookie("token", getCookieOptions({ includeMaxAge: false }))
          .clearCookie(
            "refreshToken",
            getCookieOptions({ includeMaxAge: false, path: "/auth/refresh" })
          )
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(401)
          .send({ message: "Failed to refresh token: Missing new tokens." });
      }

      const userPayload = jwt.decode(newIdToken); // Decode the new ID token to get user info

      const user = {
        id: userPayload.sub,
        email: userPayload.email,
        // Add other attributes from userPayload if available and desired in your custom JWT
        // e.g., name: userPayload.name || userPayload.given_name,
        // phone: userPayload.phone_number || null,
      };

      //NEW custom JWT from the new Cognito tokens
      const newJwtToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" }); // custom JWT short-lived

      reply
        .setCookie(
          "token",
          newJwtToken,
          getCookieOptions({ includeMaxAge: true })
        )
        .setCookie(
          "refreshToken",
          newCognitoRefreshToken || cognitoRefreshToken,
          getCookieOptions({
            includeMaxAge: true,
            maxAge: 30 * 24 * 60 * 60 * 1000,
            path: "/auth/refresh", // IMPORTANT: Only send this cookie to the refresh endpoint
          })
        )
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(200)
        .send({ message: "Token refreshed successfully", user });
    } catch (err) {
      console.error("🔴 Refresh token general error:", err);
      reply
        .clearCookie("token", getCookieOptions({ includeMaxAge: false }))
        .clearCookie(
          "refreshToken",
          getCookieOptions({ includeMaxAge: false, path: "/auth/refresh" })
        )
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500) // Changed to 500 for unexpected errors during refresh
        .send({
          error: "InternalServerError",
          message:
            "An unexpected error occurred during token refresh. Please try again or log in.",
        });
    }
  });
}
