import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";

export async function checkUserRoutes(app) {
  app.post("/auth/checkuser", async (req, reply) => {
    const { email } = req.body;

    if (!email) {
      return reply.status(400).send({ error: "Email is required" });
    }

    const region = process.env.XYVO_REGION;
    const customerUserPoolId = process.env.COGNITO_USER_POOL_ID;
    const sellerUserPoolId = process.env.COGNITO_SELLER_POOL_ID;

    const cognitoClient = new CognitoIdentityProviderClient({ region });

    const foundAccounts = [];

    try {
      const customerCommand = new AdminGetUserCommand({
        UserPoolId: customerUserPoolId,
        Username: email,
      });

      await cognitoClient.send(customerCommand);

      foundAccounts.push({ type: "Customer", poolId: customerUserPoolId });
    } catch (err) {
      if (err.name !== "UserNotFoundException") {
        console.error("Cognito customer pool error:", err);
      }
    }

    try {
      const sellerCommand = new AdminGetUserCommand({
        UserPoolId: sellerUserPoolId,
        Username: email,
      });
      await cognitoClient.send(sellerCommand);
      foundAccounts.push({ type: "Seller", poolId: sellerUserPoolId });
    } catch (err) {
      if (err.name !== "UserNotFoundException") {
        console.error("Cognito seller pool error:", err);
      }
    }

    reply
      .header("Access-Control-Allow-Origin", req.headers.origin)
      .header("Access-Control-Allow-Credentials", "true")
      .send({ accounts: foundAccounts });
  });
}
