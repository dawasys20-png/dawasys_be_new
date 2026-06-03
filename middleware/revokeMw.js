const requireApiKey = (req, res, next) => {
  const key = req.headers["x-api-key"];
  if (key !== process.env.ADMIN_API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
};

module.exports = requireApiKey;