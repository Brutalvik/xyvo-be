// routes/signout.mjs
import { getCookieOptions } from "../utils/cookieOptions.mjs";

/**
 * Registers the /auth/signout route
 * @param {import('fastify').FastifyInstance} app
 */
export async function signoutRoute(app) {
  app.post("/auth/signout", async (req, reply) => {
    const origin = req.headers.origin;

    reply
      .clearCookie("token", getCookieOptions({ includeMaxAge: false }))
      .clearCookie("x-token", {
        ...getCookieOptions({ includeMaxAge: false }),
        httpOnly: false,
      })
      .clearCookie(
        "refreshToken",
        getCookieOptions({ includeMaxAge: false, path: "/auth/refresh" })
      )
      .header("Access-Control-Allow-Origin", origin || "*")
      .header("Access-Control-Allow-Credentials", "true")
      .status(200)
      .send({ message: "Successfully signed out." });
  });
}
