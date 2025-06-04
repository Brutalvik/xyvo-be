// routes/signin.mjs
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";

const jwtSecret = process.env.JWT_SECRET;

/**
 * Registers the /auth/signin route
 * @param {import('fastify').FastifyInstance} app
 */
export async function signinRoutes(app) {
  app.post("/auth/signin", async (req, reply) => {
    try {
      const { idToken } = req.body;

      if (!idToken) {
        return reply.status(400).send({ error: "idToken is required" });
      }

      // TODO: verify the Cognito idToken if desired

      const payload = { email: "user@example.com" }; // extract from idToken if verifying
      const token = jwt.sign(payload, jwtSecret, { expiresIn: "1h" });

      reply
        .setCookie("token", token, getCookieOptions({ includeMaxAge: true }))
        .header("Access-Control-Allow-Origin", req.headers.origin || "*")
        .header("Access-Control-Allow-Credentials", "true")
        .send({ message: "Login successful" });
    } catch (err) {
      req.log.error(err);
      reply.status(500).send({ error: "Internal Server Error" });
    }
  });
}
