// routes/check-user.mjs
/**
 * Registers the /auth/check-user route
 * @param {import('fastify').FastifyInstance} app
 */
export async function checkUserRoutes(app) {
  app.post("/auth/check-user", async (req, reply) => {
    try {
      const { email } = req.body;

      const response = await fetch(
        `https://cognito-idp.${process.env.REGION}.amazonaws.com/`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.AdminGetUser",
          },
          body: JSON.stringify({
            UserPoolId: process.env.COGNITO_USER_POOL_ID,
            Username: email,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        // User doesn't exist
        return reply.status(200).send({ exists: false });
      }

      // User exists
      return reply.status(200).send({ exists: true });
    } catch (err) {
      req.log.error(err);
      return reply.status(500).send({ message: "Failed to check user" });
    }
  });
}
