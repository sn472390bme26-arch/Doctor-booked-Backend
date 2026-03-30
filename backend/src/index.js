"use strict";
require("dotenv").config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const path = require("path");

// ── Initialise DB (creates tables if needed) ──────────────────────────────────
require("./db/init");

const { setupWebSocket } = require("./services/ws");

// ── Routes ────────────────────────────────────────────────────────────────────
const authRoutes      = require("./routes/auth");
const hospitalRoutes  = require("./routes/hospitals");
const doctorRoutes    = require("./routes/doctors");
const bookingRoutes   = require("./routes/bookings");
const tokenRoutes     = require("./routes/tokens");
const patientRoutes   = require("./routes/patients");

const app = express();
const PORT = process.env.PORT || 4000;

// ── Allowed CORS origins ──────────────────────────────────────────────────────
const allowedOrigins = (process.env.CORS_ORIGINS || "http://localhost:3000")
  .split(",")
  .map(s => s.trim());

// ── Global middleware ─────────────────────────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (curl, mobile apps) or listed origins
    if (!origin || allowedOrigins.includes(origin)) cb(null, true);
    else cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));
app.use(express.json({ limit: "20mb" }));
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// ── Rate limiting ─────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." },
});
app.use("/api/", limiter);

// Stricter limiter on auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many login attempts, please try again later." },
});
app.use("/api/auth/", authLimiter);

// ── Static file serving (hospital photos) ────────────────────────────────────
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || "./uploads");
app.use("/uploads", express.static(UPLOAD_DIR));

// ── API Routes ────────────────────────────────────────────────────────────────
app.use("/api/auth",      authRoutes);
app.use("/api/hospitals", hospitalRoutes);
app.use("/api/doctors",   doctorRoutes);
app.use("/api/bookings",  bookingRoutes);
app.use("/api/tokens",    tokenRoutes);
app.use("/api/patients",  patientRoutes);

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ── 404 catch-all ─────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: "Route not found" }));

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error(err);
  const status = err.status || 500;
  res.status(status).json({ error: err.message || "Internal server error" });
});

// ── Start HTTP + WebSocket ────────────────────────────────────────────────────
const server = http.createServer(app);
setupWebSocket(server);

server.listen(PORT, () => {
  console.log(`\n🚀  Doctor Booked API running on http://localhost:${PORT}`);
  console.log(`📡  WebSocket ready at  ws://localhost:${PORT}/ws?session=SESSION_ID`);
  console.log(`🩺  Health check:       http://localhost:${PORT}/api/health\n`);
});
