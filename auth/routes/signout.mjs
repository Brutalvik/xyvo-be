// routes/signout.mjs
import { getCookieOptions } from "../utils/cookieOptions.mjs"; // adjust path as needed

/**
 * Registers the /auth/signout route
 * @param {import('fastify').FastifyInstance} app
 */
export async function signoutRoutes(app) {
  app.post("/auth/signout", async (req, reply) => {
    reply
      .clearCookie("token", getCookieOptions({ includeMaxAge: false }))
      .header("Access-Control-Allow-Origin", req.headers.origin || "*")
      .header("Access-Control-Allow-Credentials", "true")
      .send({ message: "Logged out" });
  });
}
