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

    if (!user) {
      return reply.status(401).send({ message: "Unauthorized" });
    }

    reply.send({ user });
  });
}
