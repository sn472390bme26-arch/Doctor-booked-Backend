"use strict";
const express  = require("express");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { OAuth2Client } = require("google-auth-library");
const db       = require("../db/init");
const { verifyFirebaseToken } = require("../services/firebase-admin");

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
// Normalise phone to digits only (strip +)
function normalisePhone(phone) {
  return phone.replace(/\D/g, "");
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/patient/signup
// Called AFTER Firebase phone verification.
// Frontend sends: name, email, password, firebaseIdToken (from phone auth)
// Backend verifies token, extracts phone, creates account.
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/signup",
  [
    body("email").isEmail().normalizeEmail(),
    body("name").trim().notEmpty().withMessage("Name is required"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
    body("firebaseIdToken").notEmpty().withMessage("Phone verification token is required"),
  ],
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { email, name, password, firebaseIdToken } = req.body;

      // 1. Verify Firebase token → extract phone number
      let phoneNumber;
      try {
        const decoded = await verifyFirebaseToken(firebaseIdToken);
        phoneNumber = normalisePhone(decoded.phoneNumber); // strip + → 919876543210
      } catch (err) {
        return res.status(401).json({ error: `Phone verification failed: ${err.message}` });
      }

      // 2. Check duplicates
      if (db.prepare("SELECT id FROM users WHERE email=?").get(email))
        return res.status(409).json({ error: "An account with this email already exists. Please log in." });
      if (db.prepare("SELECT id FROM users WHERE phone=? AND role='patient'").get(phoneNumber))
        return res.status(409).json({ error: "This phone number is already registered. Please log in." });

      // 3. Create account with verified phone
      const id   = `p_${email}`;
      const hash = bcrypt.hashSync(password, 12);
      db.prepare(
        "INSERT INTO users (id, email, name, password, role, phone, phone_verified) VALUES (?,?,?,?,'patient',?,1)"
      ).run(id, email, name, hash, phoneNumber);

      console.log(`[auth signup] created: ${email} phone: ${phoneNumber}`);
      res.json({
        token: sign({ id, email, name, role: "patient" }),
        user:  { id, email, name, role: "patient" },
      });
    } catch (err) {
      console.error("[auth signup]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/patient/login
// Step 1: verify email+password → return which phone to send OTP to
// The frontend then triggers Firebase OTP to that phone
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/login",
  [body("email").isEmail().normalizeEmail(), body("password").notEmpty()],
  (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { email, password } = req.body;
      const user = db.prepare("SELECT * FROM users WHERE email=? AND role='patient'").get(email);
      if (!user) return res.status(401).json({ error: "No account found with this email. Please sign up first." });
      if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "Incorrect password." });

      if (!user.phone || !user.phone_verified) {
        // Old account without phone — log in directly, prompt to add phone
        return res.json({
          token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
          user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
          needsPhone: true,
        });
      }

      // Credentials correct + phone exists → tell frontend which phone to OTP
      // Frontend will call Firebase sendOTP, then call /patient/login-verify
      res.json({
        success: true,
        userId:  user.id,
        phone:   user.phone, // frontend uses this to call Firebase OTP
        maskedPhone: `+${user.phone.slice(0,2)}XXXXX${user.phone.slice(-4)}`,
      });
    } catch (err) {
      console.error("[auth patient/login]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/patient/login-verify
// Step 2: frontend verified OTP with Firebase → sends firebaseIdToken here
// Backend verifies token, confirms phone matches account, returns JWT
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/login-verify",
  [
    body("userId").notEmpty(),
    body("firebaseIdToken").notEmpty(),
  ],
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { userId, firebaseIdToken } = req.body;

      // Verify Firebase token
      let decoded;
      try {
        decoded = await verifyFirebaseToken(firebaseIdToken);
      } catch (err) {
        return res.status(401).json({ error: `Phone verification failed: ${err.message}` });
      }

      const user = db.prepare("SELECT * FROM users WHERE id=?").get(userId);
      if (!user) return res.status(404).json({ error: "Account not found." });

      // Confirm the verified phone matches the account's phone
      const verifiedPhone = normalisePhone(decoded.phoneNumber);
      if (verifiedPhone !== user.phone) {
        return res.status(401).json({ error: "Verified phone does not match account. Please contact support." });
      }

      console.log(`[auth login] verified: ${user.email}`);
      res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    } catch (err) {
      console.error("[auth login-verify]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/patient/google
// Google One Tap → verify Google token → if phone not verified, return needsPhone
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/google", async (req, res) => {
  try {
    if (!googleClient || !GOOGLE_CLIENT_ID)
      return res.status(503).json({ error: "Google login is not configured." });

    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: "Google credential is required." });

    const ticket  = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload?.email) return res.status(401).json({ error: "Invalid Google credential." });

    const { email, name, sub: googleId } = payload;
    let user = db.prepare("SELECT * FROM users WHERE email=? AND role='patient'").get(email);

    if (!user) {
      const id   = `p_${email}`;
      const hash = bcrypt.hashSync(`google_${googleId}_${Date.now()}`, 10);
      db.prepare("INSERT INTO users (id, email, name, password, role, phone_verified) VALUES (?,?,?,?,'patient',0)")
        .run(id, email, name || email.split("@")[0], hash);
      user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
      console.log(`[auth google] created: ${email}`);
    }

    // If phone already verified → straight in
    if (user.phone && user.phone_verified) {
      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    }

    // Needs phone verification
    return res.json({ needsPhone: true, userId: user.id, name: user.name, email: user.email });

  } catch (err) {
    console.error("[auth google]", err.message);
    if (err.message?.includes("Token used too late") || err.message?.includes("Invalid token"))
      return res.status(401).json({ error: "Google sign-in expired. Please try again." });
    res.status(500).json({ error: "Google login failed. Please try again." });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/patient/google-verify-phone
// After Google login, user verified phone via Firebase → save phone to account
// ─────────────────────────────────────────────────────────────────────────────
router.post("/patient/google-verify-phone",
  [body("userId").notEmpty(), body("firebaseIdToken").notEmpty()],
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { userId, firebaseIdToken } = req.body;

      let decoded;
      try {
        decoded = await verifyFirebaseToken(firebaseIdToken);
      } catch (err) {
        return res.status(401).json({ error: `Phone verification failed: ${err.message}` });
      }

      const user = db.prepare("SELECT * FROM users WHERE id=?").get(userId);
      if (!user) return res.status(404).json({ error: "Account not found." });

      const phoneNumber = normalisePhone(decoded.phoneNumber);

      // Check phone not already used by another account
      const taken = db.prepare("SELECT id FROM users WHERE phone=? AND id!=?").get(phoneNumber, userId);
      if (taken) return res.status(409).json({ error: "This phone is already registered to another account." });

      db.prepare("UPDATE users SET phone=?, phone_verified=1 WHERE id=?").run(phoneNumber, userId);
      console.log(`[auth google] phone saved: ${user.email} → ${phoneNumber}`);

      res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    } catch (err) {
      console.error("[auth google-verify-phone]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Doctor login ──────────────────────────────────────────────────────────────
router.post("/doctor/login",
  [body("code").trim().notEmpty(), body("phone").trim().notEmpty()],
  (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { code, phone } = req.body;
      const doctor = db.prepare("SELECT * FROM doctors WHERE UPPER(code)=UPPER(?)").get(code.trim());
      if (!doctor)                       return res.status(401).json({ error: "Invalid access code. Please check with your admin." });
      if (!(doctor.phone || "").trim())  return res.status(401).json({ error: "No phone number set for this doctor. Contact admin." });
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
