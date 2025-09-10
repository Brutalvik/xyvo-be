import { query } from "../utils/db.mjs";
import { verifyJwt } from "../middleware/verifyJwt.mjs";

export async function notificationRoutes(app) {
  // GET all notifications for organization
  app.get("/notifications", { preHandler: verifyJwt }, async (req, reply) => {
    const orgId = req.user?.organizationId;

    try {
      const res = await query(
        "SELECT * FROM notifications WHERE organization_id = $1 ORDER BY created_at DESC",
        [orgId]
      );
      return reply.send({ success: true, notifications: res.rows });
    } catch (err) {
      req.log.error("GET /notifications error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to fetch notifications" });
    }
  });

  // GET notification by ID
  app.get(
    "/notifications/:id",
    { preHandler: verifyJwt },
    async (req, reply) => {
      try {
        const res = await query("SELECT * FROM notifications WHERE id = $1", [
          req.params.id,
        ]);
        if (!res.rows.length)
          return reply
            .status(404)
            .send({ success: false, error: "Notification not found" });

        return reply.send({ success: true, notification: res.rows[0] });
      } catch (err) {
        req.log.error("GET /notifications/:id error:", err);
        return reply
          .status(500)
          .send({ success: false, error: "Failed to fetch notification" });
      }
    }
  );

  // POST new notification
  app.post("/notifications", { preHandler: verifyJwt }, async (req, reply) => {
    const organization_id = req.user?.organizationId;
    const created_by = req.user?.id;

    const fields = {};
    const images = [];

    try {
      // iterate over all parts (fields + files)
      for await (const part of req.parts()) {
        if (part.file) {
          // it's a file
          const filePath = `uploads/${Date.now()}-${part.filename}`;
          await part.toFile(filePath); // save file
          images.push(filePath);
        } else {
          // it's a regular field
          fields[part.fieldname] = part.value;
        }
      }

      const { title, description } = fields;

      if (!title || !description || !organization_id || !created_by) {
        return reply
          .status(400)
          .send({ success: false, error: "Missing required fields" });
      }

      const res = await query(
        `INSERT INTO notifications (title, description, images, organization_id, created_by)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
        [title, description, images, organization_id, created_by]
      );

      return reply
        .status(201)
        .send({ success: true, notification: res.rows[0] });
    } catch (err) {
      req.log.error("POST /notifications error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to create notification" });
    }
  });

  // PATCH notification
  app.patch(
    "/notifications/:id",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const fields = req.body;
      const allowed = ["title", "description", "images"];
      const updates = [];
      const values = [];
      let idx = 1;

      for (const key of allowed) {
        if (key in fields) {
          updates.push(`${key} = $${idx++}`);
          values.push(fields[key]);
        }
      }

      if (!updates.length)
        return reply
          .status(400)
          .send({ success: false, error: "Nothing to update" });

      values.push(req.params.id);

      try {
        const res = await query(
          `UPDATE notifications SET ${updates.join(
            ", "
          )}, updated_at = NOW() WHERE id = $${idx} RETURNING *`,
          values
        );
        return reply.send({ success: true, notification: res.rows[0] });
      } catch (err) {
        req.log.error("PATCH /notifications/:id error:", err);
        return reply
          .status(500)
          .send({ success: false, error: "Failed to update notification" });
      }
    }
  );

  // DELETE notification
  app.delete(
    "/notifications/:id",
    { preHandler: verifyJwt },
    async (req, reply) => {
      try {
        await query("DELETE FROM notifications WHERE id = $1", [req.params.id]);
        return reply.send({ success: true, message: "Notification deleted" });
      } catch (err) {
        req.log.error("DELETE /notifications/:id error:", err);
        return reply
          .status(500)
          .send({ success: false, error: "Failed to delete notification" });
      }
    }
  );
}
