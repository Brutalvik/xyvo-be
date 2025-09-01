// routes/resetPassword.mjs
import {
  CognitoIdentityProviderClient,
  ForgotPasswordCommand,
  ConfirmForgotPasswordCommand,
  AdminGetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";

/**
 * resetPasswordRoutes(app)
 *
 * Provides:
 *  - POST /auth/reset-password   -> sends a reset code to the user's email (Cognito ForgotPassword)
 *  - POST /auth/confirm-reset    -> confirms the code and sets the new password (Cognito ConfirmForgotPassword)
 *
 * IMPORTANT: There is no safe Cognito API to "verify code only" without setting the password.
 * The frontend should collect both code + newPassword and call confirm-reset.
 */
export async function resetPasswordRoutes(app) {
  const region = process.env.XYVO_REGION;
  const clientId = process.env.COGNITO_CLIENT_ID;
  const clientSecret = process.env.COGNITO_CLIENT_SECRET;
  const userPoolId = process.env.COGNITO_USER_POOL_ID;

  if (!region) {
    console.warn("XYVO_REGION not set");
  }
  if (!clientId) {
    console.warn("COGNITO_CLIENT_ID not set");
  }
  if (!userPoolId) {
    console.warn("COGNITO_USER_POOL_ID not set — AdminGetUser will not work");
  }

  const cognitoClient = new CognitoIdentityProviderClient({ region });

  // Helper: compute secret hash only when clientSecret exists
  async function computeSecretHashIfNeeded(username) {
    if (!clientSecret || !clientId) return undefined;
    const { calculateSecretHash } = await import("../utils/helpers.mjs");
    return calculateSecretHash(username, clientId, clientSecret);
  }

  // ---------- 1) Send reset code ----------
  app.post("/auth/reset-password", async (req, reply) => {
    try {
      const { email } = req.body || {};
      if (!email) {
        return reply.status(400).send({ error: "MissingParameter", message: "Email is required" });
      }

      // Optional: check user exists in Cognito first (admin call)
      if (userPoolId) {
        try {
          await cognitoClient.send(new AdminGetUserCommand({
            UserPoolId: userPoolId,
            Username: email,
          }));
          // If AdminGetUserCommand succeeds, user exists
        } catch (adminErr) {
          // AdminGetUserCommand returns UserNotFoundException when not present
          if (adminErr.name === "UserNotFoundException") {
            return reply.status(404).send({ error: "UserNotFound", message: "User does not exist" });
          }
          // For other admin errors, continue to return a 500
          req.log.error("AdminGetUser error:", adminErr);
          return reply.status(500).send({ error: "CognitoAdminGetUserError", message: "Failed to verify user existence" });
        }
      }

      const secretHash = await computeSecretHashIfNeeded(email);

      const forgotPasswordCommand = new ForgotPasswordCommand({
        ClientId: clientId,
        Username: email,
        ...(secretHash ? { SecretHash: secretHash } : {}),
      });

      await cognitoClient.send(forgotPasswordCommand);

      // Success: Cognito will send the code to the user's email (or phone if configured)
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(200).send({
            message: "Reset code sent to the user's email (if account exists in Cognito).",
      });
    } catch (err) {
      req.log.error("Cognito forgot-password error:", err?.name || err);
      // Map common Cognito errors to friendly messages / status codes
      if (err.name === "UserNotFoundException") {
        return reply.status(404).send({ error: "UserNotFound", message: "User does not exist" });
      }
      if (err.name === "InvalidParameterException") {
        return reply.status(400).send({ error: "InvalidParameter", message: err.message || "Invalid parameter" });
      }
      // generic fallback
      return reply.status(500).send({ error: err.name || "ForgotPasswordError", message: "Failed to send reset code" });
    }
  });

  // ---------- 2) Confirm reset: verify code and set new password ----------
  app.post("/auth/confirm-reset", async (req, reply) => {
    try {
      const { email, code, newPassword } = req.body || {};
      if (!email || !code || !newPassword) {
        return reply.status(400).send({ error: "MissingParameter", message: "Email, code, and newPassword are required" });
      }

      const secretHash = await computeSecretHashIfNeeded(email);

      const confirmCommand = new ConfirmForgotPasswordCommand({
        ClientId: clientId,
        Username: email,
        ConfirmationCode: code,
        Password: newPassword,
        ...(secretHash ? { SecretHash: secretHash } : {}),
      });

      await cognitoClient.send(confirmCommand);

      // If Cognito returns successfully, the password was changed and the code was valid
      return reply
        .header("Access-Control-Allow-Origin", req.headers.origin)
        .header("Access-Control-Allow-Credentials", "true")
        .status(200)
        .send({ message: "Password has been reset successfully" });
    } catch (err) {
      req.log.error("Cognito confirm-reset error:", err?.name || err);
      // Map common errors
      if (err.name === "CodeMismatchException" || err.name === "ExpiredCodeException") {
        return reply.status(400).send({ error: err.name, message: "Invalid or expired code" });
      }
      if (err.name === "UserNotFoundException") {
        return reply.status(404).send({ error: "UserNotFound", message: "User does not exist" });
      }
      if (err.name === "InvalidPasswordException") {
        return reply.status(400).send({ error: "InvalidPassword", message: err.message || "Password does not meet requirements" });
      }
      // generic fallback
      return reply.status(500).send({ error: err.name || "ConfirmResetError", message: "Failed to confirm reset" });
    }
  });

  // Note: There is no separate "verify code only" endpoint due to Cognito API limitations.
  // The frontend should call /auth/confirm-reset with both code and newPassword to verify.
}
