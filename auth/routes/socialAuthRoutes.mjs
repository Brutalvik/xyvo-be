// routes/socialAuthRoutes.mjs
import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminUpdateUserAttributesCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { jwtVerify, createRemoteJWKSet } from "jose";
import jwt from "jsonwebtoken";
import { getCookieOptions } from "../utils/cookieOptions.mjs";
import { formatPhoneE164 } from "../utils/helpers.mjs";

export async function socialAuthRoute(app) {
  const region = process.env.XYVO_REGION;
  const userPoolId = process.env.COGNITO_USER_POOL_ID;
  const clientId = process.env.COGNITO_CLIENT_ID;
  const clientSecret = process.env.COGNITO_CLIENT_SECRET;
  const redirectUri = process.env.FRONTEND_SOCIAL_CALLBACK_URL;
  const hostedDomain = process.env.COGNITO_HOSTED_UI_DOMAIN;
  const jwtSecret = process.env.JWT_SECRET;
  const cognitoClient = new CognitoIdentityProviderClient({ region });

  app.post("/auth/process-social-login", async (req, reply) => {
    const { code } = req.body;
    const origin = req.headers.origin;
    const socialIdp = "Google";

    try {
      const tokenResponse = await fetch(
        `https://${hostedDomain}/oauth2/token`,
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

      const cognitoTokens = await tokenResponse.json();
      const jwksUri = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
      const JWKS = createRemoteJWKSet(new URL(jwksUri));
      const { payload: idTokenPayload } = await jwtVerify(
        cognitoTokens.id_token,
        JWKS,
        { audience: clientId }
      );

      const cognitoUserSub = idTokenPayload.sub;
      const email = idTokenPayload.email;

      let googleProfile = null;
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
      } catch {}

      let userExists = false;
      let userDetails;

      try {
        userDetails = await cognitoClient.send(
          new AdminGetUserCommand({
            UserPoolId: userPoolId,
            Username: cognitoUserSub,
          })
        );
        userExists = true;
      } catch {}

      if (userExists && userDetails) {
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
          sub: cognitoUserSub,
          socialIdp,
        };

        const token = jwt.sign(user, jwtSecret, { expiresIn: "1h" });

        return reply
          .setCookie("token", token, getCookieOptions({ includeMaxAge: true }))
          .setCookie("x-token", token, {
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
          .send({ isLoggedIn: true, user, redirectTo: "/" });
      }

      // If user does not exist yet, prompt for completion
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .send({
          needsSignupChoice: true,
          email,
          socialIdp,
          cognitoUserSub,
          name: googleProfile?.name || "",
          givenName: googleProfile?.given_name || "",
          familyName: googleProfile?.family_name || "",
        });
    } catch (err) {
      console.error("Social login failed:", err);
      return reply
        .status(500)
        .send({ message: "Social login failed", error: err.message });
    }
  });

  app.post("/auth/complete-social-signup", async (req, reply) => {
    const {
      email,
      socialIdp,
      cognitoUserSub,
      phone,
      name,
      givenName,
      familyName,
    } = req.body;

    const origin = req.headers.origin;

    if (!email || !socialIdp || !cognitoUserSub || !phone) {
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(400)
        .send({ message: "Missing required signup fields." });
    }

    try {
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
        id: cognitoUserSub,
        email,
        name: fullName,
        phone: attrs.phone_number || formatPhoneE164(phone),
        sub: cognitoUserSub,
        socialIdp,
      };

      const token = jwt.sign(user, jwtSecret, { expiresIn: "1h" });

      reply
        .setCookie("token", token, getCookieOptions({ includeMaxAge: true }))
        .setCookie("x-token", token, {
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
          message: "Signup complete",
          redirectTo: "/",
        });
    } catch (err) {
      console.error("Social signup failed:", err);
      return reply
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(500)
        .send({ message: "Signup failed", error: err.message });
    }
  });
}
