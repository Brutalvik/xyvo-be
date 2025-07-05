import { query } from "../utils/db.mjs";

/** @param {import('fastify').FastifyInstance} app */
export async function dbHealthRoute(app) {
  app.get("/health", async () => {
    const res = await query("SELECT NOW()");
    return { status: "connected", time: res.rows[0].now };
  });
}
