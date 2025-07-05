import { query } from "../utils/db.mjs";
import { verifyJwt } from "../middleware/verifyJwt.mjs";

export async function backlogRoutes(app) {
  // GET /backlogs for a project
  app.get("/backlogs", { preHandler: verifyJwt }, async (req, reply) => {
    const projectId = req.query.projectId;

    if (!projectId)
      return reply
        .status(400)
        .send({ success: false, error: "Missing projectId" });

    try {
      const res = await query(
        "SELECT * FROM backlogs WHERE project_id = $1 ORDER BY created_at DESC",
        [projectId]
      );
      return reply.send({ success: true, backlogs: res.rows });
    } catch (err) {
      req.log.error("GET /backlogs error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to fetch backlogs" });
    }
  });

  // POST /backlogs
  app.post("/backlogs", { preHandler: verifyJwt }, async (req, reply) => {
    const {
      title,
      description,
      priority,
      status = "todo",
      estimated_time,
      sprint_id,
      project_id,
      created_by,
    } = req.body;

    if (!title || !project_id || !created_by) {
      return reply
        .status(400)
        .send({ success: false, error: "Missing required fields" });
    }

    try {
      const res = await query(
        `INSERT INTO backlogs (
          title, description, priority, status,
          estimated_time, sprint_id, project_id, created_by
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
        [
          title,
          description,
          priority,
          status,
          estimated_time,
          sprint_id,
          project_id,
          created_by,
        ]
      );
      return reply.status(201).send({ success: true, backlog: res.rows[0] });
    } catch (err) {
      req.log.error("POST /backlogs error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to create backlog" });
    }
  });

  // PATCH /backlogs/:id
  app.patch("/backlogs/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const fields = req.body;
    const allowed = [
      "title",
      "description",
      "priority",
      "status",
      "estimated_time",
      "sprint_id",
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

    if (!updates.length)
      return reply
        .status(400)
        .send({ success: false, error: "Nothing to update" });

    values.push(req.params.id);

    try {
      const res = await query(
        `UPDATE backlogs SET ${updates.join(
          ", "
        )}, updated_at = NOW() WHERE id = $${idx} RETURNING *`,
        values
      );
      return reply.send({ success: true, backlog: res.rows[0] });
    } catch (err) {
      req.log.error("PATCH /backlogs/:id error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to update backlog" });
    }
  });

  // DELETE /backlogs/:id
  app.delete("/backlogs/:id", { preHandler: verifyJwt }, async (req, reply) => {
    try {
      await query("DELETE FROM backlogs WHERE id = $1", [req.params.id]);
      return reply.send({ success: true, message: "Backlog deleted" });
    } catch (err) {
      req.log.error("DELETE /backlogs/:id error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to delete backlog" });
    }
  });
}
