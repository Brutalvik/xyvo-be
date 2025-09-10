// index.mjs
import dotenv from "dotenv";
import awsLambdaFastify from "@fastify/aws-lambda";
import fastify from "fastify";
import fastifyCors from "@fastify/cors";
import fastifyCookie from "fastify-cookie";
import multipart from "@fastify/multipart";

dotenv.config();

import { signupRoute } from "./routes/signup.mjs";
import { socialAuthRoute } from "./routes/socialAuthRoutes.mjs";
import { signinRoute } from "./routes/signin.mjs";
import { refreshRoute } from "./routes/refresh.mjs";
import { signoutRoute } from "./routes/signout.mjs";
import { dbHealthRoute } from "./routes/dbHealth.mjs";

import { userRoutes } from "./routes/users.mjs";
import { organizationRoutes } from "./routes/organization.mjs";
import { teamRoutes } from "./routes/teams.mjs";
import { teamMemberRoutes } from "./routes/teamMembers.mjs";
import { userPermissionRoutes } from "./routes/userPermissions.mjs";
import { projectRoutes } from "./routes/projects.mjs";
import { sprintRoutes } from "./routes/sprints.mjs";
import { backlogRoutes } from "./routes/backlogs.mjs";
import { docsRoutes } from "./routes/routes.mjs";
import { permissionsRoutes } from "./routes/permissions.mjs";
import { resetPasswordRoutes } from "./routes/resetPassword.mjs";
import { resendVerificationRoute } from "./routes/resendVerification.mjs";
import { verifyCodeRoute } from "./routes/verifyCode.mjs";
import { notificationRoutes } from "./routes/notifcations.mjs";

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
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  preflight: true,
});

app.register(fastifyCookie);

// enable multipart support
app.register(multipart, {
  limits: {
    fileSize: 10 * 1024 * 1024, // 10 MB per file
  },
});

app.addContentTypeParser(
  "application/json",
  { parseAs: "string" },
  (req, body, done) => {
    try {
      if (!body || body.trim() === "") {
        return done(null, {});
      }
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
await app.register(signoutRoute);
await app.register(dbHealthRoute);
await app.register(userRoutes);
await app.register(organizationRoutes);
await app.register(teamRoutes);
await app.register(teamMemberRoutes);
await app.register(userPermissionRoutes);
await app.register(projectRoutes);
await app.register(sprintRoutes);
await app.register(backlogRoutes);
await app.register(docsRoutes);
await app.register(permissionsRoutes);
await app.register(resetPasswordRoutes);
await app.register(resendVerificationRoute);
await app.register(verifyCodeRoute);
await app.register(notificationRoutes);

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
