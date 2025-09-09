import { verifyToken } from "../utils/helpers.mjs";

export async function verifyJwt(req, reply) {
  // Try both cookies and headers
  const token =
    req.cookies?.token ||            // httpOnly cookie
    req.cookies?.["x-token"] ||      // frontend-readable cookie
    req.headers["x-token"] ||        // custom header
    req.headers["authorization"];    // fallback

  if (!token) {
    return reply
      .status(401)
      .send({ error: "Unauthorized: No token provided" });
  }

  const decoded = verifyToken(token);

  if (!decoded) {
    return reply
      .status(401)
      .send({ error: "Unauthorized: Invalid token" });
  }

  req.user = decoded;
}
