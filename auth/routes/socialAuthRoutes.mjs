import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminAddUserToGroupCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { jwtVerify, createRemoteJWKSet } from "jose";
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";

export async function socialAuthRoutes(app) {
  app.post("/auth/process-social-login", async (req, reply) => {
    const { code } = req.body;

    const region = process.env.XYVO_REGION;
    const customerUserPoolId = process.env.COGNITO_USER_POOL_ID;
    const sellerUserPoolId = process.env.COGNITO_SELLER_POOL_ID;
    const clientId = process.env.COGNITO_CLIENT_ID;
    const clientSecret = process.env.COGNITO_CLIENT_SECRET;
    const redirectUri = process.env.FRONTEND_SOCIAL_CALLBACK_URL;
    const cognitoHostedUiDomain = process.env.COGNITO_HOSTED_UI_DOMAIN;
    const jwtSecret = process.env.JWT_SECRET;

    const origin = req.headers.origin;

    if (!cognitoHostedUiDomain) {
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ message: "Cognito Hosted UI domain not configured." });
    }

    const cognitoClient = new CognitoIdentityProviderClient({ region });

    let cognitoTokens;
    let idTokenPayload;
    const socialIdpType = "Google"; // This can be dynamic based on the social login provider

    try {
      const tokenResponse = await fetch(
        `https://${cognitoHostedUiDomain}/oauth2/token`,
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
        return reply
          .header("Access-Control-Allow-Origin", origin)
          .header("Access-Control-Allow-Credentials", "true")
          .status(400)
          .send({
            message: errorData.error_description || "Token exchange failed",
          });
      }

      cognitoTokens = await tokenResponse.json();

      const jwksUri = `https://cognito-idp.${region}.amazonaws.com/${customerUserPoolId}/.well-known/jwks.json`;
      const JWKS = createRemoteJWKSet(new URL(jwksUri));
      const { payload } = await jwtVerify(cognitoTokens.id_token, JWKS, {
        audience: clientId,
      });

      idTokenPayload = payload;
    } catch (error) {
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({
          message: "Social login failed",
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
      if (customerUser.UserAttributes) {
        existingAccounts.push({ type: "Customer", poolId: customerUserPoolId });
      }
    } catch {
      // User not found in Customer pool
      if (existingAccounts.length > 0) {
        return reply
          .header("Access-Control-Allow-Origin", origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({
            needsSignupChoice: false,
            email,
            socialIdp: socialIdpType,
            cognitoUserSub,
            accountType: existingAccounts[0].type,
          });
      }
    }

    try {
      const sellerUser = await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: sellerUserPoolId,
          Username: email,
        })
      );
      if (sellerUser.UserAttributes) {
        existingAccounts.push({ type: "Seller", poolId: sellerUserPoolId });
      }
    } catch {
      // User not found in Seller pool
      if (existingAccounts.length > 0) {
        return reply
          .header("Access-Control-Allow-Origin", origin)
          .header("Access-Control-Allow-Credentials", "true")
          .send({
            needsSignupChoice: false,
            email,
            socialIdp: socialIdpType,
            cognitoUserSub,
            accountType: existingAccounts[0].type,
          });
      }
    }

    return reply
      .header("Access-Control-Allow-Origin", origin)
      .header("Access-Control-Allow-Credentials", "true")
      .send({
        needsSignupChoice: true,
        email,
        socialIdp: socialIdpType,
        cognitoUserSub,
      });
  });

  app.post("/auth/complete-social-signup", async (req, reply) => {
    const { email, accountType, socialIdp, cognitoUserSub } = req.body;

    const cognitoClient = new CognitoIdentityProviderClient({ region });
    const origin = req.headers.origin;

    if (!accountType) {
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({ message: "Account type is required." });
    }

    if (!email || !socialIdp || !cognitoUserSub) {
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({ message: "Missing required signup fields." });
    }

    let userPoolId;
    if (accountType === "Customer") {
      userPoolId = customerUserPoolId;
    } else if (accountType === "Seller") {
      userPoolId = sellerUserPoolId;
    } else {
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({ message: "Invalid account type." });
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

      const attrs = userDetails.UserAttributes.reduce((acc, attr) => {
        acc[attr.Name] = attr.Value;
        return acc;
      }, {});

      const name =
        attrs.name ||
        `${attrs.given_name || ""} ${attrs.family_name || ""}`.trim();

      const user = {
        id: userDetails.Username,
        email,
        name,
        accountType,
        group: accountType === "Seller" ? "Sellers" : "Customers",
      };

      const jwtToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" });

      reply
        .setCookie("token", jwtToken, getCookieOptions({ includeMaxAge: true }))
        .setCookie("x-token", jwtToken, {
          ...getCookieOptions({ includeMaxAge: true }),
          httpOnly: false,
        })
        .setCookie(
          "refreshToken",
          cognitoUserSub,
          getCookieOptions({
            includeMaxAge: true,
            maxAge: 30 * 24 * 60 * 60 * 1000,
            path: "/auth/refresh",
          })
        )
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({
          isLoggedIn: true,
          user,
          message: `Successfully registered as ${accountType}`,
          redirectTo: "/",
        });
    } catch (error) {
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({
          message: "Failed to complete social signup",
          details: error.message,
        });
    }
  });
}
