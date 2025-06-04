// --- Helpers ---
export function calculateSecretHash(username, clientId, clientSecret) {
  return crypto
    .createHmac("sha256", clientSecret)
    .update(username + clientId)
    .digest("base64");
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, jwtSecret);
  } catch (err) {
    return null;
  }
}
