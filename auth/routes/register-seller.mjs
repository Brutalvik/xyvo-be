import pkg from "@aws-sdk/client-cognito-identity-provider";
import { SellerProfileService } from "../services/sellerProfileService.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";

const {
  CognitoIdentityProviderClient,
  SignUpCommand,
  AdminConfirmSignUpCommand,
  AdminAddUserToGroupCommand,
  AdminInitiateAuthCommand,
  AdminGetUserCommand,
} = pkg;

export async function registerSellerRoutes(app) {
  const cognitoClient = new CognitoIdentityProviderClient({
    region: process.env.XYVO_REGION,
  });
  const sellerProfileService = new SellerProfileService(
    process.env.XYVO_REGION,
    process.env.SELLERS_TABLE_NAME
  );

  app.post("/auth/register-seller", async (request, reply) => {
    const {
      firstName,
      lastName,
      email,
      phone,
      password,
      businessName,
      businessAddress,
    } = request.body;

    try {
      const secretHash = calculateSecretHash(
        email,
        process.env.COGNITO_CLIENT_ID_SELLERS,
        process.env.COGNITO_CLIENT_SECRET_SELLERS
      );

      const signUpCommand = new SignUpCommand({
        ClientId: process.env.COGNITO_CLIENT_ID_SELLERS,
        Username: email,
        Password: password,
        SecretHash: secretHash,
        UserAttributes: [
          { Name: "given_name", Value: firstName },
          { Name: "family_name", Value: lastName },
          { Name: "phone_number", Value: phone },
          { Name: "email", Value: email },
          { Name: "custom:business_name", Value: businessName },
        ],
      });
      const signUpResult = await cognitoClient.send(signUpCommand);

      const cognitoUserId = signUpResult.UserSub;

      const confirmSignUpCommand = new AdminConfirmSignUpCommand({
        UserPoolId: process.env.COGNITO_SELLER_POOL_ID,
        Username: email,
      });
      await cognitoClient.send(confirmSignUpCommand);

      const addUserToGroupCommand = new AdminAddUserToGroupCommand({
        UserPoolId: process.env.COGNITO_SELLER_POOL_ID,
        Username: email,
        GroupName: "Sellers",
      });
      await cognitoClient.send(addUserToGroupCommand);

      const sellerProfile = {
        sellerId: cognitoUserId,
        businessName,
        businessAddress,
        businessEmail: email,
        businessPhone: phone,
        contactFirstName: firstName,
        contactLastName: lastName,
        createdAt: new Date().toISOString(),
      };
      await sellerProfileService.createSellerProfile(sellerProfile);

      const initiateAuthCommand = new AdminInitiateAuthCommand({
        UserPoolId: process.env.COGNITO_SELLER_POOL_ID,
        ClientId: process.env.COGNITO_CLIENT_ID_SELLERS,
        AuthFlow: "ADMIN_NO_SRP_AUTH",
        AuthParameters: {
          USERNAME: email,
          PASSWORD: password,
          SECRET_HASH: secretHash,
        },
      });
      const authResponse = await cognitoClient.send(initiateAuthCommand);

      const adminGetUserCommand = new AdminGetUserCommand({
        UserPoolId: process.env.COGNITO_SELLER_POOL_ID,
        Username: email,
      });
      const adminGetUserResponse = await cognitoClient.send(
        adminGetUserCommand
      );

      const userGroups =
        adminGetUserResponse.UserGroups?.map((group) => group.GroupName) || [];
      const userAttributes =
        adminGetUserResponse.UserAttributes?.reduce((acc, attr) => {
          acc[attr.Name] = attr.Value;
          return acc;
        }, {}) || {};

      reply.status(201).send({
        message: "Seller account created and logged in",
        user: {
          sub: cognitoUserId,
          name:
            `${userAttributes.given_name || ""} ${
              userAttributes.family_name || ""
            }`.trim() || email,
          given_name: userAttributes.given_name,
          family_name: userAttributes.family_name,
          email: email,
          phone_number: userAttributes.phone_number,
          business_name: userAttributes["custom:business_name"],
          groups: userGroups,
        },
        session: authResponse.AuthenticationResult,
      });
    } catch (error) {
      request.log.error("Seller registration error:", error);
      if (error.name === "UsernameExistsException") {
        reply.code(409).send({ message: "Email already registered." });
      } else {
        reply.code(500).send({
          message: "Failed to register seller account",
          details: error.message,
        });
      }
    }
  });
}
