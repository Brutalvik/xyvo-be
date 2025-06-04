import awsLambdaFastify from "@fastify/aws-lambda";
import fastify from "fastify";
import fastifyCors from "@fastify/cors";
import dotenv from "dotenv";
import cookie from "fastify-cookie";

//ROUTES
import { signinRoutes } from "./routes/signin.mjs";
import { registerRoutes } from "./routes/register.mjs";
import { checkUserRoutes } from "./routes/check-user.mjs";
import { refreshTokenRoute } from "./routes/refresh-token.mjs";
import { meRoute } from "./routes/me.mjs";
import { signoutRoutes } from "./routes/signout.mjs";

dotenv.config();

const app = fastify({ logger: true });

// --- CORS Configuration ---
app.register(fastifyCors, {
  origin: ["http://localhost:3000", process.env.FRONTEND_URL_VERCEL],
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"],
});

app.register(cookie);

// Parse JSON bodies
app.addContentTypeParser(
  "application/json",
  { parseAs: "string" },
  (req, body, done) => {
    try {
      const json = JSON.parse(body);
      done(null, json);
    } catch (err) {
      done(err);
    }
  }
);

// --- Routes ---

// Register user in Cognito
await app.register(registerRoutes);

//Check user in Cognito
await app.register(checkUserRoutes);

// Login: set secure cookie with JWT
await app.register(signinRoutes);

// Logout: clear cookie
await app.register(signoutRoutes);

// Authenticated user info
await app.register(meRoute);

// Refresh token
await app.register(refreshTokenRoute);

// --- Lambda Export ---
export const handler = awsLambdaFastify(app);

// Local dev mode
if (process.env.NODE_ENV === "development") {
  app.listen({ port: 5000 }, (err) => {
    if (err) {
      console.error("Startup error:", err);
      process.exit(1);
    }
    console.log("Local API running at http://localhost:5000");
  });
}
