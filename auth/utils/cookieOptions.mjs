export function getCookieOptions({ includeMaxAge = false } = {}) {
  const isProd = process.env.NODE_ENV === "production";

  const options = {
    httpOnly: true,
    sameSite: isProd ? "None" : "Lax",
    secure: isProd,
    path: "/",
    domain: isProd ? ".xyvo.ca" : "localhost",
  };

  if (includeMaxAge) {
    // 1 hour in seconds
    options.maxAge = 3600;
  }

  return options;
}
