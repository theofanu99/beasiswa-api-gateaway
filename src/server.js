require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { createProxyMiddleware } = require("http-proxy-middleware");

const app = express();

const PORT = Number(process.env.PORT || 3000);

/*
|--------------------------------------------------------------------------
| AUTHENTICATION
|--------------------------------------------------------------------------
*/

function authenticateGateway(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        message: "Access token diperlukan"
      });
    }

    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({
        message: "Format authorization tidak valid"
      });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;

    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "Access token sudah expired"
      });
    }

    return res.status(401).json({
      message: "Access token tidak valid"
    });
  }
}

/*
|--------------------------------------------------------------------------
| PERMISSION
|--------------------------------------------------------------------------
*/

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
        message: "Tidak memiliki permission"
      });
    }

    next();
  };
}

/*
|--------------------------------------------------------------------------
| ROLE
|--------------------------------------------------------------------------
*/

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

function requireAnyRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        message: "User belum terautentikasi"
      });
    }

    const roles = req.user.roles || [];

    const allowed = roles.some((role) =>
      allowedRoles.includes(role)
    );

    if (!allowed) {
      return res.status(403).json({
        message: "Tidak memiliki role yang diperlukan"
      });
    }

    next();
  };
}

/*
|--------------------------------------------------------------------------
| FORWARD USER IDENTITY
|--------------------------------------------------------------------------
|
| JWT diverifikasi di Gateway.
| Gateway kemudian meneruskan identity user ke service internal.
|
*/

function forwardUserIdentity(req, res, next) {
  if (!req.user || !req.user.sub) {
    return res.status(401).json({
      message: "Identity user tidak valid"
    });
  }

  /*
   * Hapus header dari client terlebih dahulu.
   * Jadi client tidak bisa spoof x-user-id / x-user-roles.
   */

  delete req.headers["x-user-id"];
  delete req.headers["x-user-roles"];

  req.headers["x-user-id"] = String(req.user.sub);

  req.headers["x-user-roles"] = (
    req.user.roles || []
  ).join(",");

  next();
}

/*
|--------------------------------------------------------------------------
| RATE LIMIT
|--------------------------------------------------------------------------
*/

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: "Terlalu banyak request. Silakan coba lagi nanti."
  }
});

app.use(limiter);

/*
|--------------------------------------------------------------------------
| CORS
|--------------------------------------------------------------------------
*/

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
  })
);

/*
|--------------------------------------------------------------------------
| HEALTH CHECK
|--------------------------------------------------------------------------
*/

app.get("/health", (req, res) => {
  res.json({
    service: "api-gateway",
    status: "OK"
  });
});

/*
|--------------------------------------------------------------------------
| PROXY CONFIG
|--------------------------------------------------------------------------
*/

const proxyOptions = {
  changeOrigin: true,
  logLevel: "warn",

  on: {
    error(err, req, res) {
      console.error("PROXY ERROR:", err.message);

      if (!res.headersSent) {
        res.status(502).json({
          message: "Service tujuan tidak dapat dihubungi"
        });
      }
    }
  }
};

/*
|--------------------------------------------------------------------------
| MENUS
|--------------------------------------------------------------------------
*/

app.get(
  "/api/menus",
  authenticateGateway,
  requirePermission("menu.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL,
    pathFilter: "/api/menus"
  })
);

app.get(
  "/api/menus/role/:roleId",
  authenticateGateway,
  requirePermission("menu.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL
  })
);

app.put(
  "/api/menus/role/:roleId",
  authenticateGateway,
  requirePermission("role.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL
  })
);

app.post(
  "/api/menus",
  authenticateGateway,
  requirePermission("menu.create"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL,
    pathFilter: "/api/menus"
  })
);

app.patch(
  "/api/menus/:id",
  authenticateGateway,
  requirePermission("menu.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL
  })
);

app.delete(
  "/api/menus/:id",
  authenticateGateway,
  requirePermission("menu.delete"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL
  })
);

/*
|--------------------------------------------------------------------------
| RBAC SERVICE
|--------------------------------------------------------------------------
*/

/*
 * Auth tidak membutuhkan access token.
 *
 * Jangan menggunakan:
 *
 * app.use("/api/auth", proxy)
 *
 * karena prefix /api/auth dapat terpotong.
 */

app.use(
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL,
    pathFilter: "/api/auth"
  })
);

/*
|--------------------------------------------------------------------------
| USERS
|--------------------------------------------------------------------------
*/

app.get(
  "/api/users",
  authenticateGateway,
  requirePermission("user.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL,
    pathFilter: "/api/users"
  })
);

app.post(
  "/api/users",
  authenticateGateway,
  requirePermission("user.create"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL,
    pathFilter: "/api/users"
  })
);

app.patch(
  "/api/users/:id",
  authenticateGateway,
  requirePermission("user.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL,
    pathFilter: "/api/users/:id"
  })
);

app.delete(
  "/api/users/:id",
  authenticateGateway,
  requirePermission("user.delete"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL,
    pathFilter: "/api/users/:id"
  })
);

/*
|--------------------------------------------------------------------------
| ROLES
|--------------------------------------------------------------------------
*/

app.get(
  "/api/roles",
  authenticateGateway,
  requirePermission("role.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL,
    pathFilter: "/api/roles"
  })
);

app.post(
  "/api/roles",
  authenticateGateway,
  requirePermission("role.create"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL,
    pathFilter: "/api/roles"
  })
);

app.patch(
  "/api/roles/:id",
  authenticateGateway,
  requirePermission("role.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL
  })
);

app.put(
  "/api/roles/:id/permissions",
  authenticateGateway,
  requirePermission("role.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL
  })
);

app.delete(
  "/api/roles/:id",
  authenticateGateway,
  requirePermission("role.delete"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL
  })
);

/*
|--------------------------------------------------------------------------
| PERMISSIONS
|--------------------------------------------------------------------------
*/

app.get(
  "/api/permissions",
  authenticateGateway,
  requirePermission("permission.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.RBAC_SERVICE_URL,
    pathFilter: "/api/permissions"
  })
);

/*
|--------------------------------------------------------------------------
| MASTER SERVICE - BEASISWA
|--------------------------------------------------------------------------
|
| GET /api/beasiswa/aktif
| Public.
|
| Applicant harus dapat melihat program aktif
| sebelum login.
|
*/

app.get(
  "/api/beasiswa/aktif",
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.MASTER_SERVICE_URL,
    pathFilter: "/api/beasiswa/aktif"
  })
);

app.get(
  "/api/beasiswa",
  authenticateGateway,
  requirePermission("beasiswa.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.MASTER_SERVICE_URL,
    pathFilter: "/api/beasiswa"
  })
);

app.post(
  "/api/beasiswa",
  authenticateGateway,
  requirePermission("beasiswa.create"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.MASTER_SERVICE_URL
  })
);

app.patch(
  "/api/beasiswa/:id",
  authenticateGateway,
  requirePermission("beasiswa.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.MASTER_SERVICE_URL
  })
);

app.delete(
  "/api/beasiswa/:id",
  authenticateGateway,
  requirePermission("beasiswa.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.MASTER_SERVICE_URL
  })
);

/*
|--------------------------------------------------------------------------
| MASTER SERVICE - PERSYARATAN
|--------------------------------------------------------------------------
*/

app.get(
  "/api/persyaratan",
  authenticateGateway,
  requirePermission("beasiswa.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.MASTER_SERVICE_URL
  })
);

app.get(
  "/api/persyaratan/:id",
  authenticateGateway,
  requirePermission("beasiswa.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.MASTER_SERVICE_URL
  })
);

app.post(
  "/api/persyaratan",
  authenticateGateway,
  requirePermission("beasiswa.create"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.MASTER_SERVICE_URL
  })
);

app.patch(
  "/api/persyaratan/:id",
  authenticateGateway,
  requirePermission("beasiswa.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.MASTER_SERVICE_URL
  })
);

app.delete(
  "/api/persyaratan/:id",
  authenticateGateway,
  requirePermission("beasiswa.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.MASTER_SERVICE_URL
  })
);

/*
|--------------------------------------------------------------------------
| TRANSACTION - PENDAFTARAN
|--------------------------------------------------------------------------
|
| Applicant:
|
| pendaftaran.read
| pendaftaran.create
| pendaftaran.update
| pendaftaran.submit
|
*/

app.get(
  "/api/pendaftaran",
  authenticateGateway,
  requirePermission("pendaftaran.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.TRANSACTION_SERVICE_URL
  })
);

app.get(
  "/api/pendaftaran/:id",
  authenticateGateway,
  requirePermission("pendaftaran.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.TRANSACTION_SERVICE_URL
  })
);

app.post(
  "/api/pendaftaran",
  authenticateGateway,
  requirePermission("pendaftaran.create"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.TRANSACTION_SERVICE_URL
  })
);

app.patch(
  "/api/pendaftaran/:id",
  authenticateGateway,
  requirePermission("pendaftaran.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.TRANSACTION_SERVICE_URL
  })
);

app.post(
  "/api/pendaftaran/:id/submit",
  authenticateGateway,
  requirePermission("pendaftaran.submit"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.TRANSACTION_SERVICE_URL
  })
);

/*
|--------------------------------------------------------------------------
| SELEKSI ADMINISTRASI
|--------------------------------------------------------------------------
|
| Hanya:
| VERIFIKATOR
| ADMIN
|
*/

app.post(
  "/api/pendaftaran/:pendaftaranId/seleksi-administrasi",
  authenticateGateway,
  requireAnyRole("VERIFIKATOR", "ADMIN"),
  requirePermission("verifikasi.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.TRANSACTION_SERVICE_URL
  })
);

/*
|--------------------------------------------------------------------------
| SELEKSI WAWANCARA
|--------------------------------------------------------------------------
|
| Hanya:
| LEMBAGA SELEKSI
| ADMIN
|
*/

app.post(
  "/api/pendaftaran/:pendaftaranId/seleksi-wawancara",
  authenticateGateway,
  requireAnyRole("LEMBAGA SELEKSI", "ADMIN"),
  requirePermission("wawancara.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.TRANSACTION_SERVICE_URL
  })
);

/*
|--------------------------------------------------------------------------
| HASIL SELEKSI
|--------------------------------------------------------------------------
|
| LEMBAGA SELEKSI
| ADMIN
|
*/

app.post(
  "/api/pendaftaran/:pendaftaranId/hasil-seleksi",
  authenticateGateway,
  requireAnyRole("LEMBAGA SELEKSI", "ADMIN"),
  requirePermission("wawancara.update"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.TRANSACTION_SERVICE_URL
  })
);

/*
|--------------------------------------------------------------------------
| DOCUMENT SERVICE
|--------------------------------------------------------------------------
|
| Permission sekarang ditegakkan di Gateway:
|
| POST   /api/dokumen/upload
|        -> dokumen.upload
|
| GET    /api/dokumen/pendaftaran/:id
|        -> dokumen.read
|
| GET    /api/dokumen/:id
|        -> dokumen.read
|
| DELETE /api/dokumen/:id
|        -> dokumen.delete
|
*/

app.post(
  "/api/dokumen/upload",
  authenticateGateway,
  requirePermission("dokumen.upload"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.DOCUMENT_SERVICE_URL
  })
);

app.get(
  "/api/dokumen/pendaftaran/:pendaftaranId",
  authenticateGateway,
  requirePermission("dokumen.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.DOCUMENT_SERVICE_URL
  })
);

app.get(
  "/api/dokumen/:id",
  authenticateGateway,
  requirePermission("dokumen.read"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.DOCUMENT_SERVICE_URL
  })
);

app.delete(
  "/api/dokumen/:id",
  authenticateGateway,
  requirePermission("dokumen.delete"),
  forwardUserIdentity,
  createProxyMiddleware({
    ...proxyOptions,
    target: process.env.DOCUMENT_SERVICE_URL
  })
);

/*
|--------------------------------------------------------------------------
| 404
|--------------------------------------------------------------------------
*/

app.use((req, res) => {
  res.status(404).json({
    message: "Endpoint tidak ditemukan"
  });
});

/*
|--------------------------------------------------------------------------
| ERROR HANDLER
|--------------------------------------------------------------------------
*/

app.use((err, req, res, next) => {
  console.error(err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    message: "Internal server error"
  });
});

/*
|--------------------------------------------------------------------------
| SERVER
|--------------------------------------------------------------------------
*/

app.listen(PORT, () => {
  console.log(`API Gateway berjalan di http://localhost:${PORT}`);
});