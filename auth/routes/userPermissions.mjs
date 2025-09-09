import { query } from "../utils/db.mjs";
import { verifyJwt } from "../middleware/verifyJwt.mjs";

export async function userPermissionRoutes(app) {
  // GET all permissions
  app.get(
    "/user-permissions",
    { preHandler: verifyJwt },
    async (req, reply) => {
      try {
        const res = await query(
          "SELECT * FROM user_permissions ORDER BY granted_at DESC"
        );
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, user_permissions: res.rows });
      } catch (err) {
        req.log.error("GET /user-permissions error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({ success: false, error: "Failed to fetch user permissions" });
      }
    }
  );

  // GET permissions by user
  app.get(
    "/user-permissions/user/:userId",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const { userId } = req.params;
      try {
        const res = await query(
          "SELECT * FROM user_permissions WHERE user_id = $1 ORDER BY granted_at DESC",
          [userId]
        );
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, user_permissions: res.rows });
      } catch (err) {
        req.log.error("GET /user-permissions/user/:userId error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({ success: false, error: "Failed to fetch user permissions" });
      }
    }
  );

  // GET permissions by resource type + ID (team, project, organization, etc.)
  app.get(
    "/user-permissions/resource/:resourceType/:resourceId",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const { resourceType, resourceId } = req.params;
      try {
        const res = await query(
          "SELECT * FROM user_permissions WHERE resource_type = $1 AND resource_id = $2 ORDER BY granted_at DESC",
          [resourceType, resourceId]
        );
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, user_permissions: res.rows });
      } catch (err) {
        req.log.error("GET /user-permissions/resource/:type/:id error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({
            success: false,
            error: "Failed to fetch resource permissions",
          });
      }
    }
  );

  // POST assign permission
  app.post(
  "/user-permissions",
  { preHandler: verifyJwt },
  async (req, reply) => {
    const {
      user_id,
      resource_type,
      resource_id,
      permission,
      expires_at = null,
    } = req.body || {};

    if (!user_id || !resource_type || !resource_id || !permission) {
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({ success: false, error: "Missing required fields" });
    }

    try {
      const granted_by = req.user?.id || null;
      let permsToAssign = [];

      if (permission === "admin:full") {
        // Full admin → all permissions in the DB
        const resAll = await query("SELECT key FROM permissions");
        permsToAssign = resAll.rows.map((r) => r.key);
      } else {
        // Look up the category of the selected permission
        const permRes = await query(
          "SELECT category FROM permissions WHERE key = $1",
          [permission]
        );

        if (!permRes.rows[0]) {
          return reply
            .status(400)
            .send({ success: false, error: "Invalid permission key" });
        }

        const category = permRes.rows[0].category;

        // If permission contains "full" or "crud", assign all permissions in same category
        if (permission.includes("full") || permission.includes("crud")) {
          const allInCategory = await query(
            "SELECT key FROM permissions WHERE category = $1",
            [category]
          );
          permsToAssign = allInCategory.rows.map((r) => r.key);
        } else {
          // Otherwise assign the single permission
          permsToAssign = [permission];
        }
      }

      // Insert permissions if they don't exist
      const inserted = [];
      for (const perm of permsToAssign) {
        const res = await query(
          `INSERT INTO user_permissions (
             user_id, resource_type, resource_id, permission, granted_by, granted_at, expires_at
           )
           SELECT $1, $2, $3, $4, $5, NOW(), $6
           WHERE NOT EXISTS (
             SELECT 1 FROM user_permissions
             WHERE user_id = $1 AND resource_type = $2 AND resource_id = $3 AND permission = $4
           )
           RETURNING *`,
          [user_id, resource_type, resource_id, perm, granted_by, expires_at]
        );

        if (res.rows[0]) inserted.push(res.rows[0]);
      }

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(201)
        .send({
          success: true,
          message: "Permissions assigned",
          user_permissions: inserted,
        });
    } catch (err) {
      console.error("ERROR:", err);
      req.log.error("POST /user-permissions error:", err);

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to assign user permission" });
    }
  }
);



  // PATCH update permission
  app.patch(
    "/user-permissions/:id",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const { id } = req.params;
      const { permission, expires_at } = req.body || {};

      if (!permission) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ success: false, error: "Missing permission" });
      }

      try {
        const res = await query(
          `UPDATE user_permissions SET permission = $1, expires_at = $2 WHERE id = $3 RETURNING *`,
          [permission, expires_at, id]
        );

        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, user_permission: res.rows[0] });
      } catch (err) {
        req.log.error("PATCH /user-permissions/:id error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({ success: false, error: "Failed to update user permission" });
      }
    }
  );

  // DELETE revoke permission
  app.delete(
    "/user-permissions/:id",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const { id } = req.params;

      try {
        await query("DELETE FROM user_permissions WHERE id = $1", [id]);

        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, message: "User permission deleted" });
      } catch (err) {
        req.log.error("DELETE /user-permissions/:id error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({ success: false, error: "Failed to delete user permission" });
      }
    }
  );
}
