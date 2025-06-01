import awsLambdaFastify from "@fastify/aws-lambda";
import fastify from "fastify";
import dotenv from "dotenv";
import {
  DynamoDBClient,
  PutItemCommand,
  GetItemCommand,
} from "@aws-sdk/client-dynamodb";
import { z } from "zod";

dotenv.config();

const app = fastify({ logger: true });

const REGION = process.env.AWS_REGION || "us-east-2";
const dynamoClient = new DynamoDBClient({ region: REGION });

const registerSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2),
  preferred_locale: z.string().optional(),
});

const emailOnlySchema = z.object({
  email: z.string().email(),
});

if (!REGION) {
  console.error("Missing AWS_REGION in environment variables.");
  process.exit(1);
}

app.decorate("dynamo", dynamoClient);

app.get("/health", async (_, reply) =>
  reply.status(200).send({ message: "API is Healthy", status: "ok" })
);

app.get("/", async (request, reply) => {
  return {
    message: "Welcome to XYVO SmartAI Shopping API",
    version: "1.0.0",
    routes: [
      {
        method: "GET",
        path: "/auth/users/check",
        description: "Check if user exists",
      },
    ],
  };
});

app.post("/users/register", async (request, reply) => {
  const body = request.body;
  const parse = registerSchema.safeParse(body);

  if (!parse.success) {
    return reply
      .status(400)
      .send({ error: "Invalid user data", details: parse.error.errors });
  }

  const { email, name, preferred_locale } = parse.data;

  const command = new PutItemCommand({
    TableName: "Users",
    Item: {
      email: { S: email },
      name: { S: name },
      created_at: { S: new Date().toISOString() },
      session_token: { S: "" },
      session_expiry: { N: "0" },
      is_verified: { BOOL: false },
      preferred_locale: { S: preferred_locale || "en-US" },
      role: { S: "user" },
    },
    ConditionExpression: "attribute_not_exists(email)",
  });

  try {
    await app.dynamo.send(command);
    return reply.status(201).send({ message: "User registered successfully" });
  } catch (err) {
    if (err.name === "ConditionalCheckFailedException") {
      return reply.status(409).send({ error: "User already exists" });
    }
    app.log.error(err);
    return reply.status(500).send({ error: "Internal server error" });
  }
});

app.post("/users/check", async (request, reply) => {
  const body = request.body;
  const parse = emailOnlySchema.safeParse(body);

  if (!parse.success) {
    return reply
      .status(400)
      .send({ error: "Invalid email", details: parse.error.errors });
  }

  const { email } = parse.data;

  const command = new GetItemCommand({
    TableName: "Users",
    Key: {
      email: { S: email },
    },
  });

  try {
    const result = await app.dynamo.send(command);
    if (!result.Item) {
      return reply
        .status(404)
        .send({ exists: false, message: "User not found" });
    }
    return reply.status(200).send({ exists: true, user: result.Item });
  } catch (err) {
    app.log.error(err);
    return reply.status(500).send({ error: "Failed to fetch user" });
  }
});

export const handler = awsLambdaFastify(app);

if (process.env.NODE_ENV === "test") {
  app.listen({ port: 5000 }, (err) => {
    if (err) console.error(err);
    else console.log("Server listening on http://localhost:5000");
  });
}
