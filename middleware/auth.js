require("dotenv").config();
const jwt = require("jsonwebtoken");

// Auth middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET || "secret", (err, user) => {
    if (err) {
      // Distinguish "expired" from "invalid" so the client knows whether to
      // silently call /api/auth/refresh-token or force a full re-login.
      // Without this, an expired-but-otherwise-valid token looks identical
      // to a forged or corrupted one, and the client has no signal to act on.
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ error: "TokenExpired", code: "TOKEN_EXPIRED" });
      }
      return res.status(401).json({ error: "Unauthorized", code: "TOKEN_INVALID" });
    }
    req.user = user;
    next();
  });
}

module.exports = authMiddleware;
