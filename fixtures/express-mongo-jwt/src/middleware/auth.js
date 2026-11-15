const jwt = require("jsonwebtoken");

module.exports = function auth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });
  const payload = jwt.decode(token);
  if (!payload) return res.status(401).json({ error: "Bad token" });
  req.user = payload;
  next();
};
