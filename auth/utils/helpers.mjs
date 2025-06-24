// --- Helpers ---
import crypto from "crypto";
import jwt from "jsonwebtoken";

export function calculateSecretHash(username, clientId, clientSecret) {
  return crypto
    .createHmac("sha256", clientSecret)
    .update(username + clientId)
    .digest("base64");
}

export function verifyToken(token) {
  try {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) return null;

    return jwt.verify(token, jwtSecret);
  } catch (err) {
    console.error("Token verification failed:", err);
    return null;
  }
}

export const formatPhoneE164 = (raw) => {
  const digits = raw.replace(/\D/g, ""); // Remove non-numeric characters
  return `+${digits}`;
};
