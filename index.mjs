// apps/api/lambda.ts
import awsLambdaFastify from "@fastify/aws-lambda";
import fastify from "fastify";
import fastifyCookie from "@fastify/cookie";
import { Issuer, generators } from "openid-client";
import dotenv from "dotenv";

dotenv.config();

const app = fastify({ logger: true });

// Register cookie support
app.register(fastifyCookie, {
  secret: process.env.COOKIE_SECRET || "supersecret", // Needed if you later use signed cookies
  hook: "onRequest",
});

let client;

// Discover Cognito issuer and initialize OpenID Client
app.addHook("onReady", async () => {
  const issuer = await Issuer.discover(
    `https://cognito-idp.${process.env.REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`
  );
  client = new issuer.Client({
    client_id: process.env.COGNITO_CLIENT_ID,
    client_secret: process.env.COGNITO_CLIENT_SECRET,
    redirect_uris: [`${process.env.API_URL}/auth/callback`],
    response_types: ["code"],
  });
});

// Redirect to Cognito login
app.get("/auth/login", async (req, reply) => {
  const nonce = generators.nonce();
  const state = generators.state();

  req.cookies.nonce = nonce;
  req.cookies.state = state;

  const authUrl = client.authorizationUrl({
    scope: "openid email profile",
    state,
    nonce,
  });

  reply.redirect(authUrl);
});

// Handle Cognito redirect
app.get("/auth/callback", async (req, reply) => {
  try {
    const params = client.callbackParams(req.raw);

    const tokenSet = await client.callback(
      `${process.env.API_URL}/auth/callback`,
      params,
      {
        state: req.cookies.state,
        nonce: req.cookies.nonce,
      }
    );

    const userInfo = await client.userinfo(tokenSet.access_token);

    // Set HTTP-only cookie
    reply.setCookie("authToken", tokenSet.id_token, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60, // 1 hour
    });

    // Optional: also send user info
    reply.redirect(`${process.env.FRONTEND_URL}/auth/success`);
  } catch (err) {
    app.log.error("Callback failed", err);
    reply.redirect(`${process.env.FRONTEND_URL}/auth/error`);
  }
});

// Get authenticated user
app.get("/auth/user", async (req, reply) => {
  const token = req.cookies.authToken;
  if (!token) {
    return reply.status(401).send({ error: "Not authenticated" });
  }
  return reply.send({ token }); // In production, decode and verify token
});

// Logout
app.get("/auth/logout", async (req, reply) => {
  reply.clearCookie("authToken", { path: "/" });
  reply.redirect(
    `https://${process.env.COGNITO_DOMAIN}/logout?client_id=${process.env.COGNITO_CLIENT_ID}&logout_uri=${process.env.FRONTEND_URL}`
  );
});

// Export handler for AWS Lambda
export const handler = awsLambdaFastify(app);

// For local dev
if (process.env.NODE_ENV === "development") {
  app.listen({ port: 5000 }, (err) => {
    if (err) {
      console.error("Error starting server:", err);
      process.exit(1);
    }
    console.log("Server running at http://localhost:5000");
  });
}
