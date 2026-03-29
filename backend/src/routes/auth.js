"use strict";
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const db = require("../db/init");

const router = express.Router();
const SECRET = process.env.JWT_SECRET || "fallback_dev_secret";
const EXPIRES = process.env.JWT_EXPIRES_IN || "7d";
const ADMIN_CODE = process.env.ADMIN_CODE || "ADMIN-001";

function sign(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: EXPIRES });
}

// ── Patient signup ────────────────────────────────────────────────────────────
router.post(
  "/patient/signup",
  [
    body("email").isEmail().normalizeEmail(),
    body("name").trim().notEmpty(),
    body("password").isLength({ min: 6 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array()[0].msg });

    const { email, name, password } = req.body;
    const existing = db.prepare("SELECT id FROM users WHERE email=?").get(email);
    if (existing)
      return res.status(409).json({ error: "An account with this email already exists. Please log in." });

    const id = `p_${email}`;
    const hash = bcrypt.hashSync(password, 12);
    db.prepare(
      "INSERT INTO users (id, email, name, password, role) VALUES (?,?,?,?,'patient')"
    ).run(id, email, name, hash);

    const token = sign({ id, email, name, role: "patient" });
    res.json({ token, user: { id, email, name, role: "patient" } });
  }
);

// ── Patient login ─────────────────────────────────────────────────────────────
router.post(
  "/patient/login",
  [
    body("email").isEmail().normalizeEmail(),
    body("password").notEmpty(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array()[0].msg });

    const { email, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE email=? AND role='patient'").get(email);
    if (!user)
      return res.status(401).json({ error: "No account found with this email. Please sign up first." });
    if (!bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: "Incorrect password." });

    const token = sign({ id: user.id, email: user.email, name: user.name, role: "patient" });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: "patient" } });
  }
);

// ── Doctor login (code + phone as password) ───────────────────────────────────
router.post(
  "/doctor/login",
  [
    body("code").trim().notEmpty(),
    body("phone").trim().notEmpty(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array()[0].msg });

    const { code, phone } = req.body;
    const doctor = db.prepare(
      "SELECT * FROM doctors WHERE UPPER(code)=UPPER(?)"
    ).get(code.trim());

    if (!doctor)
      return res.status(401).json({ error: "Invalid access code. Please check with your admin." });

    const registered = (doctor.phone || "").trim();
    if (!registered)
      return res.status(401).json({ error: "No phone number set for this doctor. Contact admin." });
    if (phone.trim() !== registered)
      return res.status(401).json({ error: "Incorrect password. Use your registered phone number." });

    const token = sign({ id: `doc_${doctor.code}`, code: doctor.code, doctorId: doctor.id, role: "doctor" });
    res.json({
      token,
      user: { id: `doc_${doctor.code}`, code: doctor.code, doctorId: doctor.id, role: "doctor" },
    });
  }
);

// ── Admin login ───────────────────────────────────────────────────────────────
router.post(
  "/admin/login",
  [
    body("code").trim().notEmpty(),
    body("password").notEmpty(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array()[0].msg });

    const { code, password } = req.body;
    if (code.toUpperCase() !== ADMIN_CODE.toUpperCase())
      return res.status(401).json({ error: "Invalid admin code" });

    const admin = db.prepare("SELECT * FROM users WHERE role='admin' LIMIT 1").get();
    if (!admin || !bcrypt.compareSync(password, admin.password))
      return res.status(401).json({ error: "Invalid admin password" });

    const token = sign({ id: admin.id, role: "admin" });
    res.json({ token, user: { id: admin.id, role: "admin" } });
  }
);

// ── Verify token (frontend calls on page load) ────────────────────────────────
router.get("/me", (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const payload = jwt.verify(token, SECRET);
    res.json({ user: payload });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

module.exports = router;
