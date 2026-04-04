"use strict";
const express = require("express");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { OAuth2Client } = require("google-auth-library");
const db      = require("../db/init");
const { sendOTP, generateOTP, normalisePhone, isDevMode } = require("../services/sms");

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
// Clean up expired OTPs older than 15 minutes
function cleanExpiredOTPs() {
  db.prepare("DELETE FROM otp_pending WHERE expires_at < ?").run(Date.now());
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 1A — Patient signup: collect name/email/password, send OTP to phone
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/signup",
  [
    body("email").isEmail().normalizeEmail(),
    body("name").trim().notEmpty(),
    body("password").isLength({ min: 6 }),
    body("phone").trim().notEmpty().withMessage("Phone number is required"),
  ],
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { email, name, password, phone } = req.body;
      const normPhone = normalisePhone(phone);

      // Check email not already taken
      if (db.prepare("SELECT id FROM users WHERE email=?").get(email))
        return res.status(409).json({ error: "An account with this email already exists. Please log in." });

      // Check phone not already taken
      if (db.prepare("SELECT id FROM users WHERE phone=? AND role='patient'").get(normPhone))
        return res.status(409).json({ error: "This phone number is already registered. Please log in." });

      // Generate and send OTP
      const otp       = generateOTP();
      const otpId     = `otp_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
      const hash      = bcrypt.hashSync(password, 12);

      // Remove any previous pending OTPs for this phone
      db.prepare("DELETE FROM otp_pending WHERE phone=? AND context='signup'").run(normPhone);

      // Store OTP + signup data in pending table
      db.prepare(`
        INSERT INTO otp_pending (id, phone, otp, context, data, expires_at)
        VALUES (?, ?, ?, 'signup', ?, ?)
      `).run(otpId, normPhone, otp, JSON.stringify({ email, name, hash }), expiresAt);

      await sendOTP(normPhone, otp);

      const response = {
        success: true,
        otpId,
        phone: normPhone,
        message: `OTP sent to +${normPhone}. Enter it to complete registration.`,
      };

      // In dev mode, include OTP in response for easy testing
      if (isDevMode()) response.devOtp = otp;

      res.json(response);
    } catch (err) {
      console.error("[auth signup]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// STEP 1B — Patient login: verify credentials, send OTP
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/login",
  [body("email").isEmail().normalizeEmail(), body("password").notEmpty()],
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { email, password } = req.body;
      const user = db.prepare("SELECT * FROM users WHERE email=? AND role='patient'").get(email);
      if (!user) return res.status(401).json({ error: "No account found with this email. Please sign up first." });
      if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "Incorrect password." });

      // If phone is not verified yet (old accounts), skip OTP and log in directly
      if (!user.phone || !user.phone_verified) {
        return res.json({
          token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
          user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
          needsPhone: true, // tell frontend to prompt for phone after login
        });
      }

      // Send OTP to verified phone
      const otp       = generateOTP();
      const otpId     = `otp_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      const expiresAt = Date.now() + 10 * 60 * 1000;

      db.prepare("DELETE FROM otp_pending WHERE phone=? AND context='login'").run(user.phone);
      db.prepare(`
        INSERT INTO otp_pending (id, phone, otp, context, data, expires_at)
        VALUES (?, ?, ?, 'login', ?, ?)
      `).run(otpId, user.phone, otp, JSON.stringify({ userId: user.id }), expiresAt);

      await sendOTP(user.phone, otp);

      const response = {
        success: true,
        otpId,
        phone: user.phone,
        message: `OTP sent to +${user.phone}. Enter it to log in.`,
      };
      if (isDevMode()) response.devOtp = otp;
      res.json(response);
    } catch (err) {
      console.error("[auth patient/login]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// STEP 2 — Verify OTP (works for signup, login, and google)
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/verify-otp", async (req, res) => {
  try {
    cleanExpiredOTPs();
    const { otpId, otp } = req.body;
    if (!otpId || !otp) return res.status(400).json({ error: "otpId and otp are required." });

    const pending = db.prepare("SELECT * FROM otp_pending WHERE id=?").get(otpId);
    if (!pending) return res.status(400).json({ error: "OTP session not found or expired. Please request a new OTP." });
    if (Date.now() > pending.expires_at) {
      db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);
      return res.status(400).json({ error: "OTP has expired. Please request a new one." });
    }
    if (pending.attempts >= 5) {
      db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);
      return res.status(429).json({ error: "Too many wrong attempts. Please request a new OTP." });
    }
    if (pending.otp !== otp.trim()) {
      db.prepare("UPDATE otp_pending SET attempts=attempts+1 WHERE id=?").run(otpId);
      const left = 5 - (pending.attempts + 1);
      return res.status(400).json({ error: `Incorrect OTP. ${left} attempt${left !== 1 ? "s" : ""} remaining.` });
    }

    // OTP correct — process based on context
    const data = JSON.parse(pending.data || "{}");
    db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);

    if (pending.context === "signup") {
      // Create the patient account now
      const { email, name, hash } = data;
      const id = `p_${email}`;
      db.prepare(`
        INSERT INTO users (id, email, name, password, role, phone, phone_verified)
        VALUES (?, ?, ?, ?, 'patient', ?, 1)
      `).run(id, email, name, hash, pending.phone);

      const user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
      console.log(`[auth signup] verified and created: ${email} phone: ${pending.phone}`);
      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    }

    if (pending.context === "login") {
      const user = db.prepare("SELECT * FROM users WHERE id=?").get(data.userId);
      if (!user) return res.status(404).json({ error: "Account not found." });
      console.log(`[auth login] OTP verified: ${user.email}`);
      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    }

    if (pending.context === "google") {
      // Google login phone verification — account was already created, just mark phone verified
      const user = db.prepare("SELECT * FROM users WHERE id=?").get(data.userId);
      if (!user) return res.status(404).json({ error: "Account not found." });
      db.prepare("UPDATE users SET phone=?, phone_verified=1 WHERE id=?").run(pending.phone, user.id);
      console.log(`[auth google] phone verified: ${user.email} phone: ${pending.phone}`);
      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    }

    if (pending.context === "add-phone") {
      // Adding phone to existing account (old users who logged in without phone)
      const user = db.prepare("SELECT * FROM users WHERE id=?").get(data.userId);
      if (!user) return res.status(404).json({ error: "Account not found." });
      db.prepare("UPDATE users SET phone=?, phone_verified=1 WHERE id=?").run(pending.phone, user.id);
      return res.json({ success: true, message: "Phone number verified and saved." });
    }

    res.status(400).json({ error: "Unknown OTP context." });
  } catch (err) {
    console.error("[auth verify-otp]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Resend OTP
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/resend-otp", async (req, res) => {
  try {
    const { otpId } = req.body;
    const pending = db.prepare("SELECT * FROM otp_pending WHERE id=?").get(otpId);
    if (!pending) return res.status(400).json({ error: "OTP session not found. Please start over." });

    const otp       = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    db.prepare("UPDATE otp_pending SET otp=?, expires_at=?, attempts=0 WHERE id=?")
      .run(otp, expiresAt, otpId);

    await sendOTP(pending.phone, otp);
    const response = { success: true, message: `New OTP sent to +${pending.phone}.` };
    if (isDevMode()) response.devOtp = otp;
    res.json(response);
  } catch (err) {
    console.error("[auth resend-otp]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Add/update phone for existing patient (patch endpoint)
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/send-phone-otp", async (req, res) => {
  try {
    const { userId, phone } = req.body;
    if (!userId || !phone) return res.status(400).json({ error: "userId and phone are required." });
    const normPhone = normalisePhone(phone);

    // Check phone not taken by another account
    const existing = db.prepare("SELECT id FROM users WHERE phone=? AND id!=?").get(normPhone, userId);
    if (existing) return res.status(409).json({ error: "This phone number is already used by another account." });

    const otp       = generateOTP();
    const otpId     = `otp_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const expiresAt = Date.now() + 10 * 60 * 1000;

    db.prepare("DELETE FROM otp_pending WHERE phone=? AND context='add-phone'").run(normPhone);
    db.prepare(`
      INSERT INTO otp_pending (id, phone, otp, context, data, expires_at)
      VALUES (?, ?, ?, 'add-phone', ?, ?)
    `).run(otpId, normPhone, otp, JSON.stringify({ userId }), expiresAt);

    await sendOTP(normPhone, otp);
    const response = { success: true, otpId, phone: normPhone, message: `OTP sent to +${normPhone}.` };
    if (isDevMode()) response.devOtp = otp;
    res.json(response);
  } catch (err) {
    console.error("[auth send-phone-otp]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Google One Tap — auto-creates patient, then requires phone verification
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/google", async (req, res) => {
  try {
    if (!googleClient || !GOOGLE_CLIENT_ID)
      return res.status(503).json({ error: "Google login is not configured on this server." });

    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: "Google credential is required." });

    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload?.email) return res.status(401).json({ error: "Invalid Google credential." });

    const { email, name, sub: googleId } = payload;
    let user = db.prepare("SELECT * FROM users WHERE email=? AND role='patient'").get(email);

    if (!user) {
      // Create account but mark phone as unverified
      const id   = `p_${email}`;
      const hash = bcrypt.hashSync(`google_${googleId}_${Date.now()}`, 10);
      db.prepare("INSERT INTO users (id, email, name, password, role, phone_verified) VALUES (?,?,?,?,'patient',0)")
        .run(id, email, name || email.split("@")[0], hash);
      user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
      console.log(`[auth google] auto-created: ${email}`);
    }

    // If phone already verified, log straight in
    if (user.phone && user.phone_verified) {
      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    }

    // Phone not verified yet — ask frontend to collect phone
    return res.json({
      needsPhone: true,
      userId: user.id,
      name: user.name,
      email: user.email,
      message: "Please verify your phone number to complete sign-in.",
    });

  } catch (err) {
    console.error("[auth google]", err.message);
    if (err.message?.includes("Token used too late") || err.message?.includes("Invalid token"))
      return res.status(401).json({ error: "Google sign-in expired. Please try again." });
    res.status(500).json({ error: "Google login failed. Please try again." });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Google — send OTP to collected phone number
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/google-phone-otp", async (req, res) => {
  try {
    const { userId, phone } = req.body;
    if (!userId || !phone) return res.status(400).json({ error: "userId and phone are required." });
    const normPhone = normalisePhone(phone);

    const existing = db.prepare("SELECT id FROM users WHERE phone=? AND id!=?").get(normPhone, userId);
    if (existing) return res.status(409).json({ error: "This phone number is already registered to another account." });

    const otp       = generateOTP();
    const otpId     = `otp_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const expiresAt = Date.now() + 10 * 60 * 1000;

    db.prepare("DELETE FROM otp_pending WHERE phone=? AND context='google'").run(normPhone);
    db.prepare(`
      INSERT INTO otp_pending (id, phone, otp, context, data, expires_at)
      VALUES (?, ?, ?, 'google', ?, ?)
    `).run(otpId, normPhone, otp, JSON.stringify({ userId }), expiresAt);

    await sendOTP(normPhone, otp);
    const response = { success: true, otpId, phone: normPhone, message: `OTP sent to +${normPhone}.` };
    if (isDevMode()) response.devOtp = otp;
    res.json(response);
  } catch (err) {
    console.error("[auth google-phone-otp]", err.message);
    res.status(500).json({ error: err.message });
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
      if (!doctor)                      return res.status(401).json({ error: "Invalid access code. Please check with your admin." });
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
  try { res.json({ user: jwt.verify(token, SECRET) }); }
  catch { res.status(401).json({ error: "Invalid or expired token" }); }
});

module.exports = router;
