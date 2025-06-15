import pkg from "@aws-sdk/client-cognito-identity-provider";
import { SellerProfileService } from "../services/sellerProfileService.mjs";
import { calculateSecretHash } from "../utils/helpers.mjs";
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";

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

      await cognitoClient.send(
        new AdminConfirmSignUpCommand({
          UserPoolId: process.env.COGNITO_SELLER_POOL_ID,
          Username: email,
        })
      );

      await cognitoClient.send(
        new AdminAddUserToGroupCommand({
          UserPoolId: process.env.COGNITO_SELLER_POOL_ID,
          Username: email,
          GroupName: "Sellers",
        })
      );

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

      const authResponse = await cognitoClient.send(
        new AdminInitiateAuthCommand({
          UserPoolId: process.env.COGNITO_SELLER_POOL_ID,
          ClientId: process.env.COGNITO_CLIENT_ID_SELLERS,
          AuthFlow: "ADMIN_NO_SRP_AUTH",
          AuthParameters: {
            USERNAME: email,
            PASSWORD: password,
            SECRET_HASH: secretHash,
          },
        })
      );

      const token = authResponse.AuthenticationResult;
      const idToken = token?.IdToken;
      const accessToken = token?.AccessToken;
      const refreshToken = token?.RefreshToken;

      if (!idToken || !accessToken || !refreshToken) {
        return reply.status(401).send({ message: "Missing tokens" });
      }

      const getUser = await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: process.env.COGNITO_SELLER_POOL_ID,
          Username: email,
        })
      );

      const attributes = {};
      getUser.UserAttributes.forEach((attr) => {
        attributes[attr.Name] = attr.Value;
      });

      const jwtPayload = {
        id: attributes.sub,
        sub: attributes.sub,
        email: attributes.email,
        name: `${attributes.given_name || ""} ${
          attributes.family_name || ""
        }`.trim(),
        phone: attributes.phone_number || "",
        business_name: attributes["custom:business_name"],
        group: "Sellers",
      };

      const jwtToken = jwt.sign(jwtPayload, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });

      reply
        .setCookie("token", jwtToken, getCookieOptions({ includeMaxAge: true }))
        .setCookie("x-token", jwtToken, {
          path: "/",
          sameSite: "Strict",
          maxAge: 60 * 60,
        })
        .setCookie(
          "refreshToken",
          refreshToken,
          getCookieOptions({
            includeMaxAge: true,
            maxAge: 30 * 24 * 60 * 60 * 1000,
            path: "/auth/refresh",
          })
        )
        .status(201)
        .send({
          message: "Seller registered and logged in successfully",
          user: jwtPayload,
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
