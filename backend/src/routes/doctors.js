"use strict";
const express = require("express");
const { body, validationResult } = require("express-validator");
const db = require("../db/init");
const { requireAuth, requireAdmin, requireDoctorOrAdmin } = require("../middleware/auth");

const router = express.Router();

function nextDoctorCode() {
  const row = db.prepare(
    "SELECT code FROM doctors ORDER BY CAST(SUBSTR(code, INSTR(code,'-')+1) AS INTEGER) DESC LIMIT 1"
  ).get();
  if (!row) return "DOC-00001";
  const num = parseInt(row.code.replace(/\D/g, ""), 10) || 0;
  return `DOC-${String(num + 1).padStart(5, "0")}`;
}

function row2doctor(r) {
  if (!r) return null;
  return {
    id: r.id,
    hospitalId: r.hospital_id,
    code: r.code,
    name: r.name,
    specialty: r.specialty,
    phone: r.phone || "",
    bio: r.bio || "",
    photo: r.photo || null,
    price: r.price,
    consultationFee: r.consultation_fee,
    tokensPerSession: r.tokens_per_session,
    sessions: r.sessions ? r.sessions.split(",") : ["morning", "afternoon"],
    sessionTimings: r.session_timings ? JSON.parse(r.session_timings) : null,
    isAvailable: r.is_available === 1,
    yearsOfExperience: r.years_of_experience || "",
    education: r.education || "",
    languages: r.languages ? JSON.parse(r.languages) : [],
  };
}

// GET all doctors (public)
router.get("/", (req, res) => {
  let rows;
  if (req.query.hospitalId) {
    rows = db.prepare("SELECT * FROM doctors WHERE hospital_id=? ORDER BY name ASC").all(req.query.hospitalId);
  } else {
    rows = db.prepare("SELECT * FROM doctors ORDER BY name ASC").all();
  }
  res.json(rows.map(row2doctor));
});

// GET single doctor (public)
router.get("/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM doctors WHERE id=?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Doctor not found" });
  res.json(row2doctor(row));
});

// POST create doctor (admin only)
router.post(
  "/",
  requireAdmin,
  [
    body("name").trim().notEmpty().withMessage("Name is required"),
    body("specialty").trim().notEmpty().withMessage("Specialty is required"),
    body("hospitalId").trim().notEmpty().withMessage("Hospital is required"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array()[0].msg });

    const hospital = db.prepare("SELECT id FROM hospitals WHERE id=?").get(req.body.hospitalId);
    if (!hospital) return res.status(404).json({ error: "Hospital not found" });

    const code = nextDoctorCode();
    const id = `d_${Date.now()}`;
    const {
      name, specialty, hospitalId, phone = "", bio = "",
      price = 10, tokensPerSession = 20,
      sessions = ["morning", "afternoon"],
      sessionTimings = null, yearsOfExperience = "", education = "", languages = [],
    } = req.body;

    db.prepare(`
      INSERT INTO doctors
        (id, hospital_id, code, name, specialty, phone, bio, price, consultation_fee,
         tokens_per_session, sessions, session_timings, is_available,
         years_of_experience, education, languages)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)
    `).run(
      id, hospitalId, code, name, specialty, phone, bio, price, price,
      tokensPerSession,
      Array.isArray(sessions) ? sessions.join(",") : sessions,
      sessionTimings ? JSON.stringify(sessionTimings) : null,
      yearsOfExperience, education,
      languages.length ? JSON.stringify(languages) : null
    );

    res.status(201).json(row2doctor(db.prepare("SELECT * FROM doctors WHERE id=?").get(id)));
  }
);

// PATCH update doctor (admin or the doctor themselves)
router.patch("/:id", requireDoctorOrAdmin, (req, res) => {
  const row = db.prepare("SELECT * FROM doctors WHERE id=?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Doctor not found" });

  // Doctors can only update their own record
  if (req.user.role === "doctor" && req.user.doctorId !== req.params.id)
    return res.status(403).json({ error: "Cannot edit another doctor's profile" });

  const {
    specialty, hospitalId, isAvailable, bio, sessionTimings,
    yearsOfExperience, education, languages, tokensPerSession, phone,
  } = req.body;

  db.prepare(`
    UPDATE doctors SET
      specialty          = COALESCE(?, specialty),
      hospital_id        = COALESCE(?, hospital_id),
      is_available       = COALESCE(?, is_available),
      bio                = COALESCE(?, bio),
      session_timings    = COALESCE(?, session_timings),
      years_of_experience= COALESCE(?, years_of_experience),
      education          = COALESCE(?, education),
      languages          = COALESCE(?, languages),
      tokens_per_session = COALESCE(?, tokens_per_session),
      phone              = COALESCE(?, phone)
    WHERE id=?
  `).run(
    specialty ?? null,
    hospitalId ?? null,
    isAvailable !== undefined ? (isAvailable ? 1 : 0) : null,
    bio ?? null,
    sessionTimings ? JSON.stringify(sessionTimings) : null,
    yearsOfExperience ?? null,
    education ?? null,
    languages ? JSON.stringify(languages) : null,
    tokensPerSession ?? null,
    phone ?? null,
    req.params.id
  );

  res.json(row2doctor(db.prepare("SELECT * FROM doctors WHERE id=?").get(req.params.id)));
});

// DELETE doctor (admin only)
router.delete("/:id", requireAdmin, (req, res) => {
  const row = db.prepare("SELECT * FROM doctors WHERE id=?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Doctor not found" });

  // Cancel open bookings for this doctor
  db.prepare(
    "UPDATE bookings SET status='cancelled' WHERE doctor_id=? AND status='confirmed'"
  ).run(req.params.id);

  db.prepare("DELETE FROM token_states WHERE doctor_id=?").run(req.params.id);
  db.prepare("DELETE FROM doctors WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

module.exports = router;
