import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminAddUserToGroupCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";

export async function socialAuthRoutes(app) {
  app.post("/auth/process-social-login", async (req, reply) => {
    const { code } = req.body;
    const region = process.env.XYVO_REGION;
    const customerUserPoolId = process.env.COGNITO_USER_POOL_ID;
    const sellerUserPoolId = process.env.COGNITO_SELLER_POOL_ID;
    const cognitoClient = new CognitoIdentityProviderClient({ region });

    const redirectUri = process.env.FRONTEND_SOCIAL_CALLBACK_URL;

    let cognitoTokens;
    let idTokenPayload;
    let socialIdpType = "Google";

    try {
      const clientId = process.env.COGNITO_CLIENT_ID;
      const clientSecret = process.env.COGNITO_CLIENT_SECRET;

      const tokenResponse = await fetch(
        `https://${process.env.NEXT_PUBLIC_COGNITO_CUSTOMER_DOMAIN}.auth.${region}.amazoncognito.com/oauth2/token`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization:
              "Basic " +
              Buffer.from(`${clientId}:${clientSecret}`).toString("base64"),
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: clientId,
            code: code,
            redirect_uri: redirectUri,
          }).toString(),
        }
      );

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json();
        console.error("Google social login token exchange failed:", errorData);
        throw new Error(
          errorData.error_description || "Failed to exchange code for tokens."
        );
      }

      cognitoTokens = await tokenResponse.json();
      idTokenPayload = jwt.decode(cognitoTokens.id_token);
    } catch (error) {
      console.error("Social login token exchange failed:", error);
      return reply.status(400).send({
        message: "Failed to authenticate with social provider",
        error: error.message,
      });
    }

    const email = idTokenPayload.email;
    const cognitoUserSub = idTokenPayload.sub;

    let existingAccounts = [];

    try {
      const customerUser = await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: customerUserPoolId,
          Username: email,
        })
      );
      if (customerUser.UserAttributes)
        existingAccounts.push({ type: "Customer", poolId: customerUserPoolId });
    } catch (err) {
      /* User not found is expected */
    }

    try {
      const sellerUser = await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: sellerUserPoolId,
          Username: email,
        })
      );
      if (sellerUser.UserAttributes)
        existingAccounts.push({ type: "Seller", poolId: sellerUserPoolId });
    } catch (err) {
      /* User not found is expected */
    }

    if (existingAccounts.length === 0) {
      return reply.send({
        needsSignupChoice: true,
        email,
        socialIdp: socialIdpType,
        cognitoUserSub,
      });
    } else {
      return reply.send({
        needsSignupChoice: true,
        email,
        socialIdp: socialIdpType,
        cognitoUserSub,
      });
    }
  });

  app.post("/auth/complete-social-signup", async (req, reply) => {
    const { email, accountType, socialIdp, cognitoUserSub } = req.body;
    const region = process.env.XYVO_REGION;
    const cognitoClient = new CognitoIdentityProviderClient({ region });

    if (!email || !accountType || !socialIdp || !cognitoUserSub) {
      return reply
        .status(400)
        .send({ message: "Missing required information for social signup." });
    }

    let userPoolId;
    if (accountType === "Customer") {
      userPoolId = process.env.COGNITO_USER_POOL_ID;
    } else if (accountType === "Seller") {
      userPoolId = process.env.COGNITO_SELLER_POOL_ID;
    } else {
      return reply.status(400).send({ message: "Invalid account type." });
    }

    try {
      const userDetails = await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: userPoolId,
          Username: email,
        })
      );

      if (accountType === "Seller") {
        await cognitoClient.send(
          new AdminAddUserToGroupCommand({
            UserPoolId: userPoolId,
            Username: email,
            GroupName: "Sellers",
          })
        );
      }

      const finalUser = {
        id: userDetails.Username,
        email: email,
        name: userDetails.UserAttributes.find((attr) => attr.Name === "name")
          ?.Value,
        accountType: accountType,
      };

      return reply.send({
        isLoggedIn: true,
        user: finalUser,
        message: `Successfully registered as ${accountType}`,
        redirectTo: "/",
      });
    } catch (error) {
      console.error("Error completing social signup:", error);
      return reply.status(500).send({
        message: "Failed to complete social signup",
        details: error.message,
      });
    }
  });
}
