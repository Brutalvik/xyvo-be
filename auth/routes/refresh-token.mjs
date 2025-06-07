// routes/refresh-token.mjs
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { verifyToken } from "../utils/helpers.mjs";

const jwtSecret = process.env.JWT_SECRET;

/**
 * Registers the /auth/refresh route
 * @param {import('fastify').FastifyInstance} app
 */
export async function refreshTokenRoute(app) {
  app.post("/auth/refresh", async (req, reply) => {
    const token = req.cookies.token;
    const user = verifyToken(token);

    if (!user) {
      return reply.status(401).send({ message: "Unauthorized" });
    }

    const newToken = jwt.sign({ email: user.email }, jwtSecret, {
      expiresIn: "1h",
    });

    reply
      .setCookie("token", newToken, getCookieOptions({ includeMaxAge: true }))
      .header("Access-Control-Allow-Origin", req.headers.origin || "*")
      .header("Access-Control-Allow-Credentials", "true")
      .send({ message: "Token refreshed" });
  });
}
