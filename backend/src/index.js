"use strict";
require("dotenv").config();
const express = require("express");
const http    = require("http");
const cors    = require("cors");
const helmet  = require("helmet");
const morgan  = require("morgan");
const rateLimit = require("express-rate-limit");
const path    = require("path");

require("./db/init");
const { setupWebSocket } = require("./services/ws");

const authRoutes     = require("./routes/auth");
const hospitalRoutes = require("./routes/hospitals");
const doctorRoutes   = require("./routes/doctors");
const bookingRoutes  = require("./routes/bookings");
const tokenRoutes    = require("./routes/tokens");
const patientRoutes  = require("./routes/patients");

const app  = express();
const PORT = process.env.PORT || 4000;

// ── CORS ──────────────────────────────────────────────────────────────────────
// Collect every allowed origin from the env variable, normalised
const rawOrigins = (process.env.CORS_ORIGINS || "http://localhost:3000,http://localhost:5173")
  .split(",")
  .map(s => s.trim().replace(/\/$/, "").toLowerCase())
  .filter(Boolean);

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));

// WIDE-OPEN CORS — allows every origin.
// This is the only reliable way to prevent "failed to fetch" across all
// devices, browsers, and Vercel preview URLs.
// Security is handled by JWT on every protected route instead.
app.use(cors({
  origin: true,          // reflect whatever origin the browser sends
  credentials: true,
  methods: ["GET","POST","PATCH","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","X-Requested-With"],
  optionsSuccessStatus: 200,
}));

// Ensure pre-flight OPTIONS requests always succeed immediately
app.options("*", cors({
  origin: true,
  credentials: true,
  methods: ["GET","POST","PATCH","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","X-Requested-With"],
  optionsSuccessStatus: 200,
}));

app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// ── Rate limiting ─────────────────────────────────────────────────────────────
app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." },
  skip: (req) => req.method === "OPTIONS",
}));

app.use("/api/auth/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: "Too many login attempts, please try again later." },
  skip: (req) => req.method === "OPTIONS",
}));

// ── Static uploads ────────────────────────────────────────────────────────────
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || "./uploads");
app.use("/uploads", express.static(UPLOAD_DIR));

// ── Routes ────────────────────────────────────────────────────────────────────
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

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: "Route not found" }));

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error(err);
  // Never let CORS errors silently swallow the response
  if (!res.headersSent) {
    res.status(err.status || 500).json({ error: err.message || "Internal server error" });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
const server = http.createServer(app);
setupWebSocket(server);

server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀  Doctor Booked API → http://0.0.0.0:${PORT}`);
  console.log(`📡  WebSocket        → ws://0.0.0.0:${PORT}/ws?session=ID`);
  console.log(`🩺  Health check     → http://0.0.0.0:${PORT}/api/health\n`);
});
