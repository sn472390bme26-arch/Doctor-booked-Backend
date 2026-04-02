"use strict";
const express = require("express");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { OAuth2Client } = require("google-auth-library");
const db      = require("../db/init");

const router     = express.Router();
const SECRET     = process.env.JWT_SECRET     || "fallback_dev_secret";
const EXPIRES    = process.env.JWT_EXPIRES_IN || "7d";
const ADMIN_CODE = process.env.ADMIN_CODE     || "ADMIN-001";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";

const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

function sign(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: EXPIRES });
}

function validate(req, res) {
  const e = validationResult(req);
  if (!e.isEmpty()) { res.status(400).json({ error: e.array()[0].msg }); return false; }
  return true;
}

// ── Patient signup ────────────────────────────────────────────────────────────
router.post("/patient/signup",
  [body("email").isEmail().normalizeEmail(), body("name").trim().notEmpty(), body("password").isLength({ min: 6 })],
  (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { email, name, password } = req.body;
      if (db.prepare("SELECT id FROM users WHERE email=?").get(email))
        return res.status(409).json({ error: "An account with this email already exists. Please log in." });

      const id   = `p_${email}`;
      const hash = bcrypt.hashSync(password, 12);
      db.prepare("INSERT INTO users (id, email, name, password, role) VALUES (?,?,?,?,'patient')").run(id, email, name, hash);

      res.json({ token: sign({ id, email, name, role: "patient" }), user: { id, email, name, role: "patient" } });
    } catch (err) {
      console.error("[auth signup]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Patient login ─────────────────────────────────────────────────────────────
router.post("/patient/login",
  [body("email").isEmail().normalizeEmail(), body("password").notEmpty()],
  (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { email, password } = req.body;
      const user = db.prepare("SELECT * FROM users WHERE email=? AND role='patient'").get(email);
      if (!user) return res.status(401).json({ error: "No account found with this email. Please sign up first." });
      if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "Incorrect password." });

      res.json({ token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
                 user:  { id: user.id, email: user.email, name: user.name, role: "patient" } });
    } catch (err) {
      console.error("[auth patient/login]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Google One Tap login ──────────────────────────────────────────────────────
// Receives the credential JWT from Google Identity Services
// Verifies it with Google's public keys, then logs in or auto-creates the patient
router.post("/patient/google", async (req, res) => {
  try {
    if (!googleClient || !GOOGLE_CLIENT_ID) {
      return res.status(503).json({ error: "Google login is not configured on this server." });
    }

    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: "Google credential is required." });

    // Verify the Google JWT credential — this is the secure part
    const ticket = await googleClient.verifyIdToken({
      idToken:  credential,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      return res.status(401).json({ error: "Invalid Google credential." });
    }

    const { email, name, sub: googleId } = payload;

    // Check if a patient account already exists with this email
    let user = db.prepare("SELECT * FROM users WHERE email=? AND role='patient'").get(email);

    if (!user) {
      // Auto-create patient account — no password needed (Google handles auth)
      // Use a random unusable password hash since they'll always login via Google
      const id   = `p_${email}`;
      const hash = bcrypt.hashSync(`google_${googleId}_${Date.now()}`, 10);
      db.prepare(
        "INSERT INTO users (id, email, name, password, role) VALUES (?,?,?,?,'patient')"
      ).run(id, email, name || email.split("@")[0], hash);

      user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
      console.log(`[auth google] auto-created patient: ${email}`);
    } else {
      console.log(`[auth google] existing patient login: ${email}`);
    }

    res.json({
      token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
      user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
    });

  } catch (err) {
    console.error("[auth google]", err.message);
    // Google verification failure gives a specific error
    if (err.message?.includes("Token used too late") || err.message?.includes("Invalid token")) {
      return res.status(401).json({ error: "Google sign-in expired. Please try again." });
    }
    res.status(500).json({ error: "Google login failed. Please try again." });
  }
});

// ── Doctor login ──────────────────────────────────────────────────────────────
router.post("/doctor/login",
  [body("code").trim().notEmpty(), body("phone").trim().notEmpty()],
  (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { code, phone } = req.body;
      const doctor = db.prepare("SELECT * FROM doctors WHERE UPPER(code)=UPPER(?)").get(code.trim());
      if (!doctor)                     return res.status(401).json({ error: "Invalid access code. Please check with your admin." });
      if (!(doctor.phone || "").trim()) return res.status(401).json({ error: "No phone number set for this doctor. Contact admin." });
      if (phone.trim() !== (doctor.phone || "").trim())
        return res.status(401).json({ error: "Incorrect password. Use your registered phone number." });

      const payload = { id: `doc_${doctor.code}`, code: doctor.code, doctorId: doctor.id, role: "doctor" };
      res.json({ token: sign(payload), user: payload });
    } catch (err) {
      console.error("[auth doctor/login]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Admin login ───────────────────────────────────────────────────────────────
router.post("/admin/login",
  [body("code").trim().notEmpty(), body("password").notEmpty()],
  (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { code, password } = req.body;
      if (code.toUpperCase() !== ADMIN_CODE.toUpperCase())
        return res.status(401).json({ error: "Invalid admin code" });

      const admin = db.prepare("SELECT * FROM users WHERE role='admin' LIMIT 1").get();
      if (!admin || !bcrypt.compareSync(password, admin.password))
        return res.status(401).json({ error: "Invalid admin password" });

      res.json({ token: sign({ id: admin.id, role: "admin" }), user: { id: admin.id, role: "admin" } });
    } catch (err) {
      console.error("[auth admin/login]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Verify token ──────────────────────────────────────────────────────────────
router.get("/me", (req, res) => {
  const header = req.headers.authorization || "";
  const token  = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    res.json({ user: jwt.verify(token, SECRET) });
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

module.exports = router;
