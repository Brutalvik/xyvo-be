import dotenv from "dotenv";

import awsLambdaFastify from "@fastify/aws-lambda";
import fastify from "fastify";
import fastifyCors from "@fastify/cors";
import fastifyCookie from "fastify-cookie";

dotenv.config();

//ROUTES
import { signinRoutes } from "./routes/signin.mjs";
import { registerRoutes } from "./routes/register.mjs";
import { checkUserRoutes } from "./routes/checkuser.mjs";
import { refreshTokenRoute } from "./routes/refresh.mjs";
import { meRoute } from "./routes/me.mjs";
import { signoutRoutes } from "./routes/signout.mjs";

const app = fastify({ logger: true });

// --- CORS Configuration ---
const allowedOrigins = [
  "http://localhost:3000",
  "https://xyvo.vercel.app",
  "https://www.xyvo.ca",
  "http://www.xyvo.ca",
  "https://auth.xyvo.ca",
  "https://products.xyvo.ca",
];

// --- CORS Configuration ---
app.register(fastifyCors, {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("CORS origin not allowed"), false);
    }
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
});

app.register(fastifyCookie);

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
