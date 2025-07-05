import { query } from "../utils/db.mjs";
import { verifyJwt } from "../middleware/verifyJwt.mjs";

export async function teamMemberRoutes(app) {
  // GET /team-members (all)
  app.get("/team-members", { preHandler: verifyJwt }, async (req, reply) => {
    try {
      const res = await query(
        "SELECT * FROM team_members ORDER BY joined_at DESC"
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, team_members: res.rows });
    } catch (err) {
      req.log.error("GET /team-members error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to fetch team members" });
    }
  });

  // GET /team-members/team/:teamId
  app.get(
    "/team-members/team/:teamId",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const { teamId } = req.params;

      try {
        const res = await query(
          "SELECT * FROM team_members WHERE team_id = $1 ORDER BY joined_at DESC",
          [teamId]
        );

        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, team_members: res.rows });
      } catch (err) {
        req.log.error("GET /team-members/team/:teamId error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({
            success: false,
            error: "Failed to fetch members for this team",
          });
      }
    }
  );

  // GET /team-members/user/:userId
  app.get(
    "/team-members/user/:userId",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const { userId } = req.params;

      try {
        const res = await query(
          "SELECT * FROM team_members WHERE user_id = $1 ORDER BY joined_at DESC",
          [userId]
        );

        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, team_memberships: res.rows });
      } catch (err) {
        req.log.error("GET /team-members/user/:userId error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({
            success: false,
            error: "Failed to fetch user's team memberships",
          });
      }
    }
  );

  // POST /team-members
  app.post("/team-members", { preHandler: verifyJwt }, async (req, reply) => {
    const { team_id, user_id, role = "member" } = req.body || {};

    if (!team_id || !user_id) {
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({ success: false, error: "Missing team_id or user_id" });
    }

    try {
      const result = await query(
        `INSERT INTO team_members (team_id, user_id, role, joined_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING *`,
        [team_id, user_id, role]
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(201)
        .send({ success: true, team_member: result.rows[0] });
    } catch (err) {
      req.log.error("POST /team-members error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to add member to team" });
    }
  });

  // PATCH /team-members/:id
  app.patch(
    "/team-members/:id",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const { id } = req.params;
      const { role } = req.body || {};

      if (!role) {
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({ success: false, error: "Missing role" });
      }

      try {
        const result = await query(
          `UPDATE team_members SET role = $1 WHERE id = $2 RETURNING *`,
          [role, id]
        );

        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, team_member: result.rows[0] });
      } catch (err) {
        req.log.error("PATCH /team-members/:id error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({ success: false, error: "Failed to update team member" });
      }
    }
  );

  // DELETE /team-members/:id
  app.delete(
    "/team-members/:id",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const { id } = req.params;

      try {
        await query("DELETE FROM team_members WHERE id = $1", [id]);

        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, message: "Team member removed" });
      } catch (err) {
        req.log.error("DELETE /team-members/:id error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({ success: false, error: "Failed to remove team member" });
      }
    }
  );
}
