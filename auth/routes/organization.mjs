import { query } from "../utils/db.mjs";
import { verifyJwt } from "../middleware/verifyJwt.mjs";

export async function organizationRoutes(app) {
  // GET /organizations (all orgs)
  app.get("/organizations", { preHandler: verifyJwt }, async (req, reply) => {
    try {
      const res = await query(
        "SELECT * FROM organizations ORDER BY created_at DESC"
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({ success: true, organizations: res.rows });
    } catch (err) {
      req.log.error("GET /organizations error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to fetch organizations" });
    }
  });

  // GET /organizations/:id
  app.get(
    "/organizations/:id",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const orgId = req.params.id;
      try {
        const res = await query("SELECT * FROM organizations WHERE id = $1", [
          orgId,
        ]);

        if (!res.rows.length) {
          return reply
            .header("Access-Control-Allow-Origin", req.headers.origin)
            .header("Access-Control-Allow-Credentials", "true")
            .status(404)
            .send({ success: false, error: "Organization not found" });
        }

        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, organization: res.rows[0] });
      } catch (err) {
        req.log.error("GET /organizations/:id error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({ success: false, error: "Failed to fetch organization" });
      }
    }
  );

  // POST /organizations
  app.post("/organizations", { preHandler: verifyJwt }, async (req, reply) => {
    const { name, domain, logo } = req.body || {};

    if (!name) {
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({ success: false, error: "Organization name is required" });
    }

    try {
      const result = await query(
        `INSERT INTO organizations (name, domain, logo)
         VALUES ($1, $2, $3) RETURNING *`,
        [name, domain, logo]
      );

      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(201)
        .send({ success: true, organization: result.rows[0] });
    } catch (err) {
      req.log.error("POST /organizations error:", err);
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ success: false, error: "Failed to create organization" });
    }
  });

  // PATCH /organizations/:id
  app.patch(
    "/organizations/:id",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const orgId = req.params.id;
      const fields = req.body || {};
      const allowed = ["name", "domain", "logo"];

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

      values.push(orgId);

      try {
        const result = await query(
          `UPDATE organizations SET ${updates.join(", ")}, updated_at = NOW()
         WHERE id = $${idx} RETURNING *`,
          values
        );

        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, organization: result.rows[0] });
      } catch (err) {
        req.log.error("PATCH /organizations/:id error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({ success: false, error: "Failed to update organization" });
      }
    }
  );

  // DELETE /organizations/:id
  app.delete(
    "/organizations/:id",
    { preHandler: verifyJwt },
    async (req, reply) => {
      const orgId = req.params.id;

      try {
        await query("DELETE FROM organizations WHERE id = $1", [orgId]);

        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({ success: true, message: "Organization deleted" });
      } catch (err) {
        req.log.error("DELETE /organizations/:id error:", err);
        return reply
          .header("Access-Control-Allow-Origin", req.headers.origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(500)
          .send({ success: false, error: "Failed to delete organization" });
      }
    }
  );
}
