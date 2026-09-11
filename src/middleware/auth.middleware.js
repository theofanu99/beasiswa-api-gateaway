const jwt = require("jsonwebtoken");

function authenticateGateway(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Access token diperlukan"
    });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      message: "Access token tidak valid atau sudah expired"
    });
  }
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        message: "User belum terautentikasi"
      });
    }

    const permissions = req.user.permissions || [];

    if (!permissions.includes(permission)) {
      return res.status(403).json({
        message: "Tidak memiliki permission yang diperlukan"
      });
    }

    next();
  };
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        message: "User belum terautentikasi"
      });
    }

    const roles = req.user.roles || [];

    if (!roles.includes(role)) {
      return res.status(403).json({
        message: "Tidak memiliki role yang diperlukan"
      });
    }

    next();
  };
}

module.exports = {
  authenticateGateway,
  requirePermission,
  requireRole
};