// routes/signout.mjs
import {
  CognitoIdentityProviderClient,
  RevokeTokenCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { getCookieOptions } from "../utils/cookieOptions.mjs";

/**
 * Registers the /auth/signout route
 * @param {import('fastify').FastifyInstance} app
 */
export async function signoutRoutes(app) {
  app.post("/auth/signout", async (req, reply) => {
    const cognitoRefreshToken = req.cookies.refreshToken; // Get the Cognito refresh token from cookie
    const clientId = process.env.COGNITO_CLIENT_ID;
    const region = process.env.XYVO_REGION;

    // Attempt to revoke the refresh token in Cognito
    if (cognitoRefreshToken) {
      try {
        const cognitoClient = new CognitoIdentityProviderClient({ region });
        const revokeCommand = new RevokeTokenCommand({
          ClientId: clientId,
          Token: cognitoRefreshToken, // This is the refresh token to revoke
        });
        await cognitoClient.send(revokeCommand);
        console.log("Cognito Refresh Token revoked successfully.");
      } catch (err) {
        console.error(
          "🔴 Error revoking Cognito Refresh Token:",
          err.name,
          err.message
        );
      }
    }

    // Clear cookies on the client side, regardless of server-side revocation success.
    reply
      .clearCookie("token", getCookieOptions({ includeMaxAge: false }))
      .clearCookie(
        "refreshToken",
        getCookieOptions({ includeMaxAge: false, path: "/auth/refresh" })
      ) // Clear the Cognito refresh token cookie
      .header("Access-Control-Allow-Origin", req.headers.origin)
      .header("Access-Control-Allow-Credentials", "true")
      .status(200) // 200 OK is appropriate as a message body is sent
      .send({ message: "Logged out successfully" });
  });
}
