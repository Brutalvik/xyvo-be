import { verifyToken } from "../utils/helpers.mjs";

export async function verifyJwt(req, reply) {
  const token = req.cookies?.token;

  if (!token) {
    return reply.status(401).send({ error: "Unauthorized: No token provided" });
  }

  const decoded = verifyToken(token);

  if (!decoded) {
    return reply.status(401).send({ error: "Unauthorized: Invalid token" });
  }

  req.user = decoded;
}
