import { query } from "../utils/db.mjs";
import { verifyJwt } from "../middleware/verifyJwt.mjs";

export async function userRoutes(app) {
  // GET /users
  app.get("/users", { preHandler: verifyJwt }, async (req, reply) => {
    try {
      const res = await query("SELECT * FROM users ORDER BY created_at DESC");

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, users: res.rows });
    } catch (err) {
      req.log.error("GET /users error:", err);

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to fetch users" });
    }
  });

  // GET /users/:id
  app.get("/users/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const userId = req.params.id;

    try {
      const res = await query("SELECT * FROM users WHERE id = $1", [userId]);

      if (!res.rows.length) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(404)
          .send({ success: false, error: "User not found" });
      }

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, user: res.rows[0] });
    } catch (err) {
      req.log.error("GET /users/:id error:", err);

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to fetch user" });
    }
  });

  // PATCH /users/:id
  app.patch("/users/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const userId = req.params.id;
    const fields = req.body || {};
    const allowed = [
      "name",
      "phone",
      "image",
      "role",
      "account_type",
      "organization_id",
      "timezone",
    ];

    const updates = [];
    const values = [];
    let idx = 1;

    for (const key of allowed) {
      if (key in fields) {
        updates.push(`${key} = $${idx++}`);
        values.push(fields[key]);
      }
    }

    if (!updates.length) {
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({ success: false, error: "No valid fields to update" });
    }

    values.push(userId);

    try {
      const result = await query(
        `UPDATE users SET ${updates.join(", ")}, updated_at = NOW()
         WHERE id = $${idx} RETURNING *`,
        values
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, user: result.rows[0] });
    } catch (err) {
      req.log.error("PATCH /users/:id error:", err);

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to update user" });
    }
  });

  // DELETE /users/:id
  app.delete("/users/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const userId = req.params.id;

    try {
      await query("DELETE FROM users WHERE id = $1", [userId]);

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, message: "User deleted" });
    } catch (err) {
      req.log.error("DELETE /users/:id error:", err);

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to delete user" });
    }
  });
}
