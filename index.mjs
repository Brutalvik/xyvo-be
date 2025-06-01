// apps/api/lambda.ts
import awsLambdaFastify from "@fastify/aws-lambda";
import fastify from "fastify";
import dotenv from "dotenv";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";

dotenv.config();

const app = fastify({ logger: true });

const REGION = process.env.AWS_REGION || "us-east-2";
const dynamoClient = new DynamoDBClient({ region: REGION });

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
        path: "auth/users/check",
        description: "Check if user exists",
      },
    ],
  };
});


export const handler = awsLambdaFastify(app);

if (process.env.NODE_ENV === "test") {
  app.listen({ port: 5000 }, (err) => {
    if (err) console.error(err);
    else console.log("Server listening on http://localhost:5000");
  });
}
