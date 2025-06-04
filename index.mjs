import awsLambdaFastify from "@fastify/aws-lambda";
import fastify from "fastify";
import fastifyCors from "@fastify/cors";
import dotenv from "dotenv";
import crypto from "crypto";
import cookie from "fastify-cookie";
import jwt from "jsonwebtoken";

dotenv.config();

const app = fastify({ logger: true });

const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;
const region = process.env.REGION;
const jwtSecret = process.env.JWT_SECRET;

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

// --- Helpers ---
function calculateSecretHash(username, clientId, clientSecret) {
  return crypto
    .createHmac("sha256", clientSecret)
    .update(username + clientId)
    .digest("base64");
}

function verifyToken(token) {
  try {
    return jwt.verify(token, jwtSecret);
  } catch (err) {
    return null;
  }
}

// --- Routes ---

// Register user in Cognito
app.post("/auth/register", async (req, reply) => {
  try {
    const { email, phone, password, name } = req.body;

    const secretHash = calculateSecretHash(email, clientId, clientSecret);

    const response = await fetch(
      `https://cognito-idp.${process.env.REGION}.amazonaws.com/`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-amz-json-1.1",
          "X-Amz-Target": "AWSCognitoIdentityProviderService.SignUp",
          "X-Amz-User-Agent": "aws-amplify/3.0",
        },
        body: JSON.stringify({
          ClientId: clientId,
          SecretHash: secretHash,
          Username: email,
          Password: password,
          UserAttributes: [
            { Name: "email", Value: email },
            { Name: "name", Value: name },
            { Name: "given_name", Value: name },
            { Name: "phone_number", Value: phone },
          ],
        }),
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return reply
        .status(400)
        .send({ message: data.message || "Registration error" });
    }
    const userSub = {
      id: data.UserSub,
      email: email,
      name: name,
    };
    const jwtToken = jwt.sign({ email }, jwtSecret, { expiresIn: "1h" });

    //Auto signin user
    reply
      .setCookie("token", jwtToken, {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        path: "/",
        maxAge: 3600,
      })
      .header("Access-Control-Allow-Origin", req.headers.origin || "*")
      .header("Access-Control-Allow-Credentials", "true")
      .status(201)
      .send({ user: userSub, isRegistered: true, isLoggedIn: true });

    reply.status(201).send({ user: userSub, isRegistered: true });
  } catch (error) {
    app.log.error("Registration failed", error);
    reply.status(500).send({ message: "Internal Server Error" });
  }
});

// Login: set secure cookie with JWT
app.post("/auth/signin", async (req, reply) => {
  const { email } = req.body;
  const payload = { email };
  const jwtToken = jwt.sign(payload, jwtSecret, { expiresIn: "1h" });

  reply
    .setCookie("token", jwtToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 3600,
    })
    .header("Access-Control-Allow-Origin", req.headers.origin || "*")
    .header("Access-Control-Allow-Credentials", "true")
    .send({ message: "Login successful" });
});

// Logout: clear cookie
app.post("/auth/signout", async (req, reply) => {
  reply
    .clearCookie("token", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production", // must match login!
      path: "/",
    })
    .header("Access-Control-Allow-Origin", req.headers.origin || "*")
    .header("Access-Control-Allow-Credentials", "true")
    .send({ message: "Logged out" });
});

// Authenticated user info
app.get("/auth/me", async (req, reply) => {
  const token = req.cookies.token;
  const user = verifyToken(token);

  if (!user) return reply.status(401).send({ message: "Unauthorized" });
  reply.send({ user });
});

// Refresh token
app.post("/auth/refresh", async (req, reply) => {
  const token = req.cookies.token;
  const user = verifyToken(token);

  if (!user) return reply.status(401).send({ message: "Unauthorized" });

  const newToken = jwt.sign({ email: user.email }, jwtSecret, {
    expiresIn: "1h",
  });

  reply
    .setCookie("token", newToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 3600,
    })
    .header("Access-Control-Allow-Origin", req.headers.origin || "*")
    .header("Access-Control-Allow-Credentials", "true")
    .send({ message: "Token refreshed" });
});

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
