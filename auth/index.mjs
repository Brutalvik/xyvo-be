// index.mjs
import dotenv from "dotenv";
import awsLambdaFastify from "@fastify/aws-lambda";
import fastify from "fastify";
import fastifyCors from "@fastify/cors";
import fastifyCookie from "fastify-cookie";

dotenv.config();

import { signupRoute } from "./routes/signup.mjs";
import { socialAuthRoute } from "./routes/socialAuthRoutes.mjs";
import { signinRoute } from "./routes/signin.mjs";
import { refreshRoute } from "./routes/refresh.mjs";
import { meRoute } from "./routes/me.mjs";
import { signoutRoute } from "./routes/signout.mjs";

const app = fastify({ logger: true });

const allowedOrigins = [
  "http://localhost:3000",
  "https://xyvoai.vercel.app",
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

await app.register(signupRoute);
await app.register(socialAuthRoute);
await app.register(refreshRoute);
await app.register(signinRoute);
await app.register(meRoute);
await app.register(signoutRoute);

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
