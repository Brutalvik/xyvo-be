// routes/me.mjs
import { verifyToken } from "../utils/helpers.mjs";

/**
 * Registers the /auth/me route
 * @param {import('fastify').FastifyInstance} app
 */
export async function meRoute(app) {
  app.get("/auth/me", async (req, reply) => {
    const token = req.cookies.token;

    if (!token) {
      req.log.warn("No token provided.");
      return reply
        .clearCookie("x-token", { path: "/" })
        .status(401)
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ message: "Unauthorized" });
    }

    const user = verifyToken(token);

    if (!user) {
      req.log.warn("Invalid token.");
      return reply
        .clearCookie("x-token", { path: "/" })
        .status(401)
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ message: "Unauthorized" });
    }

    return reply
      .status(200)
      .header("Access-Control-Allow-Origin", req.headers.origin)
      .header("Access-Control-Allow-Credentials", "true")
      .send({ user });
  });
}
