const jwt = require('jsonwebtoken');

function auth(req, res, next) {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401);
  try {
    const decoded = jwt.verify(token, config.get(jwt));
    next();
  } catch (error) {}
}

function go(req, res, next) {
  if (req.user.isAdmin) return res.status(403);
  next();
}
