import { query } from "../utils/db.mjs";
import { verifyJwt } from "../middleware/verifyJwt.mjs";

export async function sprintRoutes(app) {
  // GET all sprints in org
  app.get("/sprints", { preHandler: verifyJwt }, async (req, reply) => {
    const orgId = req.user?.organizationId;

    try {
      const res = await query(
        "SELECT * FROM sprints WHERE organization_id = $1 ORDER BY start_date DESC",
        [orgId]
      );
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, sprints: res.rows });
    } catch (err) {
      req.log.error("GET /sprints error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to fetch sprints" });
    }
  });

  // GET /sprints/:id
  app.get("/sprints/:id", { preHandler: verifyJwt }, async (req, reply) => {
    try {
      const res = await query("SELECT * FROM sprints WHERE id = $1", [
        req.params.id,
      ]);
      if (!res.rows.length)
        return reply
          .status(404)
          .send({ success: false, error: "Sprint not found" });
      return reply.send({ success: true, sprint: res.rows[0] });
    } catch (err) {
      req.log.error("GET /sprints/:id error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to fetch sprint" });
    }
  });

  // POST /sprints
  app.post("/sprints", { preHandler: verifyJwt }, async (req, reply) => {
    const {
      name,
      description,
      start_date,
      end_date,
      timezone,
      color,
      status = "upcoming",
      goal,
      auto_assign = false,
    } = req.body;

    const organization_id = req.user?.organizationId;
    const created_by = req.user?.id;

    if (!name || !start_date || !end_date || !organization_id || !created_by) {
      return reply
        .status(400)
        .send({ success: false, error: "Missing required fields" });
    }

    try {
      const res = await query(
        `INSERT INTO sprints (
          name, description, start_date, end_date,
          timezone, color, status, goal, auto_assign,
          organization_id, created_by
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
        [
          name,
          description,
          start_date,
          end_date,
          timezone,
          color,
          status,
          goal,
          auto_assign,
          organization_id,
          created_by,
        ]
      );
      return reply.status(201).send({ success: true, sprint: res.rows[0] });
    } catch (err) {
      req.log.error("POST /sprints error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to create sprint" });
    }
  });

  // PATCH /sprints/:id
  app.patch("/sprints/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const fields = req.body;
    const allowed = [
      "name",
      "description",
      "start_date",
      "end_date",
      "timezone",
      "color",
      "status",
      "goal",
      "auto_assign",
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
        `UPDATE sprints SET ${updates.join(
          ", "
        )}, updated_at = NOW() WHERE id = $${idx} RETURNING *`,
        values
      );
      return reply.send({ success: true, sprint: res.rows[0] });
    } catch (err) {
      req.log.error("PATCH /sprints/:id error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to update sprint" });
    }
  });

  // DELETE /sprints/:id
  app.delete("/sprints/:id", { preHandler: verifyJwt }, async (req, reply) => {
    try {
      await query("DELETE FROM sprints WHERE id = $1", [req.params.id]);
      return reply.send({ success: true, message: "Sprint deleted" });
    } catch (err) {
      req.log.error("DELETE /sprints/:id error:", err);
      return reply
        .status(500)
        .send({ success: false, error: "Failed to delete sprint" });
    }
  });
}
