import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminAddUserToGroupCommand,
  AdminUpdateUserAttributesCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { jwtVerify, createRemoteJWKSet } from "jose";
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { formatPhoneE164 } from "../utils/helpers.mjs";

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
    const cognitoClient = new CognitoIdentityProviderClient({ region });

    if (!cognitoHostedUiDomain) {
      return reply
        .status(500)
        .send({ message: "Cognito Hosted UI domain not configured." });
    }

    let cognitoTokens,
      idTokenPayload,
      googleProfile = null;
    const socialIdpType = "Google";

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
            code,
            redirect_uri: redirectUri,
          }).toString(),
        }
      );

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json();
        return reply.status(400).send({
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

      try {
        const profileRes = await fetch(
          "https://openidconnect.googleapis.com/v1/userinfo",
          {
            headers: { Authorization: `Bearer ${cognitoTokens.access_token}` },
          }
        );
        if (profileRes.ok) {
          googleProfile = await profileRes.json();
        }
      } catch {
        console.warn("Failed to fetch Google profile");
      }
    } catch (error) {
      return reply
        .status(400)
        .send({ message: "Social login failed", error: error.message });
    }

    const email = idTokenPayload.email;
    const cognitoUserSub = idTokenPayload.sub;
    const existingAccounts = [];

    try {
      await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: customerUserPoolId,
          Username: cognitoUserSub,
        })
      );
      existingAccounts.push({ type: "buyer", poolId: customerUserPoolId });
    } catch {}

    try {
      await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: sellerUserPoolId,
          Username: cognitoUserSub,
        })
      );
      existingAccounts.push({ type: "seller", poolId: sellerUserPoolId });
    } catch {}

    if (existingAccounts.length > 0) {
      const account = existingAccounts[0];
      const userDetails = await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: account.poolId,
          Username: cognitoUserSub,
        })
      );

      const attrs = Object.fromEntries(
        (userDetails.UserAttributes || []).map(({ Name, Value }) => [
          Name,
          Value,
        ])
      );

      const fullName =
        attrs.name ||
        `${attrs.given_name || ""} ${attrs.family_name || ""}`.trim() ||
        email.split("@")[0];

      const user = {
        id: cognitoUserSub,
        email,
        name: fullName,
        phone: attrs.phone_number,
        group: account.type === "buyer" ? "Buyers" : "Sellers",
        type: account.type,
        sub: cognitoUserSub,
        socialIdp: socialIdpType,
      };

      const jwtToken = jwt.sign(user, jwtSecret, { expiresIn: "1h" });

      return reply
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
          redirectTo: "/",
        });
    }

    return reply
      .header("Access-Control-Allow-Origin", origin)
      .header("Access-Control-Allow-Credentials", "true")
      .send({
        needsSignupChoice: true,
        email,
        socialIdp: socialIdpType,
        cognitoUserSub,
        name: googleProfile?.name || "",
        givenName: googleProfile?.given_name || "",
        familyName: googleProfile?.family_name || "",
      });
  });

  app.post("/auth/complete-social-signup", async (req, reply) => {
    const {
      email,
      accountType,
      socialIdp,
      cognitoUserSub,
      phone,
      name,
      givenName,
      familyName,
    } = req.body;

    const origin = req.headers.origin;
    const region = process.env.XYVO_REGION;
    const jwtSecret = process.env.JWT_SECRET;
    const customerUserPoolId = process.env.COGNITO_USER_POOL_ID;
    const sellerUserPoolId = process.env.COGNITO_SELLER_POOL_ID;
    const cognitoClient = new CognitoIdentityProviderClient({ region });

    if (!email || !accountType || !socialIdp || !cognitoUserSub || !phone) {
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({ message: "Missing required signup fields." });
    }

    const poolMap = {
      buyer: customerUserPoolId,
      seller: sellerUserPoolId,
    };

    const groupMap = {
      buyer: "Buyers",
      seller: "Sellers",
    };

    const userPoolId = poolMap[accountType];
    const groupName = groupMap[accountType];

    if (!userPoolId || !groupName) {
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({ message: "Invalid account type." });
    }

    try {
      // 🔐 Update attributes (phone, name, given_name, family_name)
      const userAttrs = [
        { Name: "phone_number", Value: formatPhoneE164(phone) },
      ];
      if (name) userAttrs.push({ Name: "name", Value: name });
      if (givenName) userAttrs.push({ Name: "given_name", Value: givenName });
      if (familyName)
        userAttrs.push({ Name: "family_name", Value: familyName });

      await cognitoClient.send(
        new AdminUpdateUserAttributesCommand({
          UserPoolId: userPoolId,
          Username: cognitoUserSub,
          UserAttributes: userAttrs,
        })
      );

      // ✅ Add to group
      await cognitoClient.send(
        new AdminAddUserToGroupCommand({
          UserPoolId: userPoolId,
          Username: cognitoUserSub,
          GroupName: groupName,
        })
      );

      // 🧾 Get user details
      const userDetails = await cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: userPoolId,
          Username: cognitoUserSub,
        })
      );

      const attrs = Object.fromEntries(
        (userDetails.UserAttributes || []).map(({ Name, Value }) => [
          Name,
          Value,
        ])
      );

      const fullName =
        attrs.name ||
        `${attrs.given_name || ""} ${attrs.family_name || ""}`.trim() ||
        email.split("@")[0];

      const user = {
        id: userDetails.Username,
        email,
        name: fullName,
        type: accountType,
        group: groupName,
        phone: attrs.phone_number || formatPhoneE164(phone),
        sub: cognitoUserSub,
        socialIdp,
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
      console.error("Social signup error:", error);
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
