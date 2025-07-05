import { query } from "../utils/db.mjs";
import { verifyJwt } from "../middleware/verifyJwt.mjs";

export async function permissionsRoutes(app) {
  // GET /permissions
  app.get("/permissions", { preHandler: verifyJwt }, async (req, reply) => {
    try {
      const res = await query(
        "SELECT * FROM permissions ORDER BY category, key"
      );
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, permissions: res.rows });
    } catch (err) {
      req.log.error("GET /permissions error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to fetch permissions" });
    }
  });
}
