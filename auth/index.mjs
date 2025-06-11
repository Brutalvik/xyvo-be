// index.mjs
import dotenv from "dotenv";
import awsLambdaFastify from "@fastify/aws-lambda";
import fastify from "fastify";
import fastifyCors from "@fastify/cors";
import fastifyCookie from "fastify-cookie";

dotenv.config();

import { signinRoutes } from "./routes/signin.mjs";
import { registerRoutes } from "./routes/register.mjs";
import { checkUserRoutes } from "./routes/checkuser.mjs";
import { refreshTokenRoute } from "./routes/refresh.mjs";
import { meRoute } from "./routes/me.mjs";
import { signoutRoutes } from "./routes/signout.mjs";
import { registerSellerRoutes } from "./routes/register-seller.mjs";
import { socialAuthRoutes } from "./routes/socialAuthRoutes.mjs";

const app = fastify({ logger: true });

const allowedOrigins = [
  "http://localhost:3000",
  "https://xyvo.vercel.app",
  "https://www.xyvo.ca",
  "http://www.xyvo.ca",
];

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

await app.register(registerRoutes);
await app.register(checkUserRoutes);
await app.register(signinRoutes);
await app.register(signoutRoutes);
await app.register(meRoute);
await app.register(refreshTokenRoute);
await app.register(registerSellerRoutes);
await app.register(socialAuthRoutes);

export const handler = awsLambdaFastify(app);

if (process.env.NODE_ENV === "development") {
  app.listen({ port: 5000 }, (err) => {
    if (err) {
      console.error("Startup error:", err);
      process.exit(1);
    }
    console.log("Local API running at http://localhost:5000");
  });
}
