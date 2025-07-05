import { query } from "../utils/db.mjs";
import { verifyJwt } from "../middleware/verifyJwt.mjs";

export async function teamRoutes(app) {
  // GET /teams
  app.get("/teams", { preHandler: verifyJwt }, async (req, reply) => {
    try {
      const organizationId = req.user?.organizationId;
      if (!organizationId) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ success: false, error: "Missing organization ID" });
      }

      const result = await query(
        "SELECT * FROM teams WHERE organization_id = $1 ORDER BY created_at DESC",
        [organizationId]
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, teams: result.rows });
    } catch (err) {
      req.log.error("GET /teams error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to fetch teams" });
    }
  });

  // GET /teams/:id
  app.get("/teams/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const teamId = req.params.id;
    try {
      const result = await query("SELECT * FROM teams WHERE id = $1", [teamId]);
      if (!result.rows.length) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(404)
          .send({ success: false, error: "Team not found" });
      }

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, team: result.rows[0] });
    } catch (err) {
      req.log.error("GET /teams/:id error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to fetch team" });
    }
  });

  // POST /teams
  app.post("/teams", { preHandler: verifyJwt }, async (req, reply) => {
    const {
      name,
      description,
      color,
      visibility = "private",
      timezone,
      tags = [],
    } = req.body || {};

    const lead_id = req.user?.id;
    const organization_id = req.user?.organizationId;

    if (!name || !lead_id || !organization_id) {
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({
          success: false,
          error: "Missing required fields: name, user, or organization",
        });
    }

    try {
      const teamRes = await query(
        `INSERT INTO teams (
          name, description, lead_id, organization_id, color, visibility, timezone, tags
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8
        ) RETURNING *`,
        [
          name,
          description,
          lead_id,
          organization_id,
          color,
          visibility,
          timezone,
          tags,
        ]
      );

      const team = teamRes.rows[0];

      // Auto-insert lead into team_members
      await query(
        `INSERT INTO team_members (team_id, user_id, role)
         VALUES ($1, $2, 'lead')`,
        [team.id, lead_id]
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(201)
        .send({ success: true, team });
    } catch (err) {
      req.log.error("POST /teams error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to create team" });
    }
  });

  // PATCH /teams/:id
  app.patch("/teams/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const teamId = req.params.id;
    const fields = req.body || {};
    const allowed = [
      "name",
      "description",
      "color",
      "visibility",
      "timezone",
      "tags",
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

    values.push(teamId); // Last value = WHERE condition

    try {
      const result = await query(
        `UPDATE teams SET ${updates.join(
          ", "
        )}, updated_at = NOW() WHERE id = $${idx} RETURNING *`,
        values
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, team: result.rows[0] });
    } catch (err) {
      req.log.error("PATCH /teams/:id error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to update team" });
    }
  });

  // DELETE /teams/:id
  app.delete("/teams/:id", { preHandler: verifyJwt }, async (req, reply) => {
    const teamId = req.params.id;

    try {
      await query("DELETE FROM teams WHERE id = $1", [teamId]);

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, message: "Team deleted" });
    } catch (err) {
      req.log.error("DELETE /teams/:id error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to delete team" });
    }
  });
}
