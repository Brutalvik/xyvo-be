// routes/register.mjs
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";

const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;
const jwtSecret = process.env.JWT_SECRET;

/**
 * Registers the /auth/register route
 * @param {import('fastify').FastifyInstance} app
 */
export async function registerRoutes(app) {
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
        email,
        name,
      };

      const jwtToken = jwt.sign({ email }, jwtSecret, { expiresIn: "1h" });

      reply
        .setCookie("token", jwtToken, getCookieOptions({ includeMaxAge: true }))
        .header("Access-Control-Allow-Origin", req.headers.origin || "*")
        .header("Access-Control-Allow-Credentials", "true")
        .status(201)
        .send({ user: userSub, isRegistered: true, isLoggedIn: true });
    } catch (error) {
      app.log.error("Registration failed", error);
      reply.status(500).send({ message: "Internal Server Error" });
    }
  });
}
