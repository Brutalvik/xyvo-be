import { query } from "../utils/db.mjs";
import { verifyJwt } from "../middleware/verifyJwt.mjs";

export async function projectRoutes(app) {
  // GET /projects (all in org)
  app.get("/projects", { preHandler: verifyJwt }, async (req, reply) => {
    try {
      const organizationId = req.user?.organizationId;

      if (!organizationId) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ success: false, error: "Missing organization ID" });
      }

      const res = await query(
        "SELECT * FROM projects WHERE organization_id = $1 ORDER BY created_at DESC",
        [organizationId]
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, projects: res.rows });
    } catch (err) {
      req.log.error("GET /projects error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to fetch projects" });
    }
  });

  // GET /projects/:id
  app.get("/projects/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const projectId = req.params.id;
    try {
      const res = await query("SELECT * FROM projects WHERE id = $1", [
        projectId,
      ]);

      if (!res.rows.length) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(404)
          .send({ success: false, error: "Project not found" });
      }

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, project: res.rows[0] });
    } catch (err) {
      req.log.error("GET /projects/:id error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to fetch project" });
    }
  });

  // POST /projects
  app.post("/projects", { preHandler: verifyJwt }, async (req, reply) => {
    const {
      name,
      description,
      color,
      status = "active",
      visibility = "private",
      tags = [],
      ai_tasks = false,
      start_date,
      end_date,
    } = req.body || {};

    const created_by = req.user?.id;
    const organization_id = req.user?.organizationId;

    if (!name || !created_by || !organization_id) {
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({
          success: false,
          error: "Missing required fields: name, organization, or user",
        });
    }

    try {
      console.log(
        `INSERT INTO projects, `,
        name,
        description,
        color,
        status,
        visibility,
        tags,
        organization_id,
        created_by,
        ai_tasks,
        start_date,
        end_date
      );
      const result = await query(
        `INSERT INTO projects (
          name, description, color, status, visibility, tags,
          organization_id, created_by, ai_tasks, start_date, end_date
        ) VALUES (
          $1, $2, $3, $4, $5, $6::text[],
          $7, $8, $9, $10, $11
        ) RETURNING *`,
        [
          name,
          description,
          color,
          status,
          visibility,
          tags,
          organization_id,
          created_by,
          ai_tasks,
          start_date,
          end_date,
        ]
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(201)
        .send({ success: true, project: result.rows[0] });
    } catch (err) {
      console.error("PROJECT INSERT ERROR:", err);
      req.log.error("POST /projects error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to create project" });
    }
  });

  // PATCH /projects/:id
  app.patch("/projects/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const projectId = req.params.id;
    const fields = req.body || {};
    const allowed = [
      "name",
      "description",
      "color",
      "status",
      "visibility",
      "tags",
      "ai_tasks",
      "start_date",
      "end_date",
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

    values.push(projectId);

    try {
      const result = await query(
        `UPDATE projects SET ${updates.join(", ")}, updated_at = NOW()
         WHERE id = $${idx} RETURNING *`,
        values
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, project: result.rows[0] });
    } catch (err) {
      req.log.error("PATCH /projects/:id error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to update project" });
    }
  });

  // DELETE /projects/:id
  app.delete("/projects/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const projectId = req.params.id;

    try {
      await query("DELETE FROM projects WHERE id = $1", [projectId]);

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, message: "Project deleted" });
    } catch (err) {
      req.log.error("DELETE /projects/:id error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to delete project" });
    }
  });
}
