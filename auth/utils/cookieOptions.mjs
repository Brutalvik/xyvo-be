export function getCookieOptions({ includeMaxAge = false } = {}) {
  const isProd = process.env.NODE_ENV === "production";

  const options = {
    httpOnly: true,
    sameSite: isProd ? "none" : "lax",
    secure: isProd,
    path: "/",
    domain: isProd ? "xyvo.ca" : "localhost",
  };

  if (includeMaxAge) {
    options.maxAge = 3600;
  }

  return options;
}
