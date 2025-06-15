// routes/me.mjs
import { verifyToken } from "../utils/helpers.mjs";

/**
 * Registers the /auth/me route
 * @param {import('fastify').FastifyInstance} app
 */
export async function meRoute(app) {
  app.get("/auth/me", async (req, reply) => {
    const token = req.cookies.token;
    const user = verifyToken(token);

    if (!token || !user) {
      req.log.warn("Unauthorized access to /auth/me");
      return reply
        .clearCookie("x-token", { path: "/" })
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(401)
        .send({ message: "Unauthorized" });
    }

    reply
      .header("Access-Control-Allow-Origin", req.headers.origin)
      .header("Access-Control-Allow-Credentials", "true")
      .status(200)
      .send({ user });
  });
}
