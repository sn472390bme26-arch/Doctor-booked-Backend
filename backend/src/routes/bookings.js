"use strict";
const express = require("express");
const { body, validationResult } = require("express-validator");
const db = require("../db/init");
const { requireAuth, requireAdmin, requireDoctorOrAdmin } = require("../middleware/auth");
const { broadcast } = require("../services/ws");

const router = express.Router();

function row2booking(r) {
  if (!r) return null;
  return {
    id: r.id,
    patientId: r.patient_id,
    patientName: r.patient_name,
    doctorId: r.doctor_id,
    doctorName: r.doctor_name,
    hospitalName: r.hospital_name,
    date: r.date,
    session: r.session,
    tokenNumber: r.token_number,
    sessionId: r.session_id,
    paymentDone: r.payment_done === 1,
    status: r.status,
    phone: r.phone || "",
    complaint: r.complaint || "",
    createdAt: r.created_at,
  };
}

// GET bookings — patient sees own, doctor sees their own, admin sees all
router.get("/", requireAuth, (req, res) => {
  let rows;
  if (req.user.role === "admin") {
    rows = db.prepare("SELECT * FROM bookings ORDER BY created_at DESC").all();
  } else if (req.user.role === "doctor") {
    rows = db.prepare(
      "SELECT * FROM bookings WHERE doctor_id=? ORDER BY date DESC, session ASC, token_number ASC"
    ).all(req.user.doctorId);
  } else {
    rows = db.prepare(
      "SELECT * FROM bookings WHERE patient_id=? ORDER BY created_at DESC"
    ).all(req.user.id);
  }
  res.json(rows.map(row2booking));
});

// GET bookings for a specific session (used by doctor dashboard & token tracker)
router.get("/session/:sessionId", requireAuth, (req, res) => {
  const rows = db.prepare(
    "SELECT * FROM bookings WHERE session_id=? ORDER BY token_number ASC"
  ).all(req.params.sessionId);
  res.json(rows.map(row2booking));
});

// POST create booking (authenticated patient)
router.post(
  "/",
  requireAuth,
  [
    body("doctorId").notEmpty(),
    body("date").matches(/^\d{4}-\d{2}-\d{2}$/),
    body("session").isIn(["morning", "afternoon", "evening"]),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array()[0].msg });

    if (req.user.role !== "patient")
      return res.status(403).json({ error: "Only patients can create bookings" });

    const { doctorId, date, session, complaint = "", phone = "" } = req.body;

    const doctor = db.prepare("SELECT * FROM doctors WHERE id=?").get(doctorId);
    if (!doctor) return res.status(404).json({ error: "Doctor not found" });

    const hospital = db.prepare("SELECT * FROM hospitals WHERE id=?").get(doctor.hospital_id);
    const sessionId = `${doctorId}_${date}_${session}`;

    // Check capacity
    const bookedCount = db.prepare(
      "SELECT COUNT(*) as c FROM bookings WHERE session_id=? AND payment_done=1 AND status!='cancelled'"
    ).get(sessionId).c;

    if (bookedCount >= doctor.tokens_per_session)
      return res.status(409).json({ error: "This session is fully booked" });

    // Check for duplicate booking by same patient in same session
    const dup = db.prepare(
      "SELECT id FROM bookings WHERE session_id=? AND patient_id=? AND status!='cancelled'"
    ).get(sessionId, req.user.id);
    if (dup) return res.status(409).json({ error: "You already have a booking in this session" });

    const tokenNumber = bookedCount + 1;
    const id = `b_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;

    const patient = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);

    // Wrap entire booking creation in a transaction so it never partially commits
    const createBookingTx = db.transaction(() => {
      // Re-check capacity inside transaction (prevents race conditions)
      const freshCount = db.prepare(
        "SELECT COUNT(*) as c FROM bookings WHERE session_id=? AND payment_done=1 AND status!='cancelled'"
      ).get(sessionId).c;
      if (freshCount >= doctor.tokens_per_session)
        throw Object.assign(new Error("This session is fully booked"), { status: 409 });

      const freshDup = db.prepare(
        "SELECT id FROM bookings WHERE session_id=? AND patient_id=? AND status!='cancelled'"
      ).get(sessionId, req.user.id);
      if (freshDup)
        throw Object.assign(new Error("You already have a booking in this session"), { status: 409 });

      const freshToken = freshCount + 1;

      db.prepare(`
        INSERT INTO bookings
          (id, patient_id, patient_name, doctor_id, doctor_name, hospital_name,
           date, session, token_number, session_id, payment_done, status, phone, complaint)
        VALUES (?,?,?,?,?,?,?,?,?,?,1,'confirmed',?,?)
      `).run(
        id, req.user.id, patient.name,
        doctorId, doctor.name,
        hospital ? hospital.name : "Unknown",
        date, session, freshToken, sessionId, phone, complaint
      );

      // Initialise or update token state
      const existing = db.prepare("SELECT * FROM token_states WHERE session_id=?").get(sessionId);
      if (existing) {
        const statuses = JSON.parse(existing.token_statuses || "{}");
        statuses[freshToken] = "red";
        db.prepare("UPDATE token_states SET token_statuses=?, updated_at=datetime('now') WHERE session_id=?")
          .run(JSON.stringify(statuses), sessionId);
      } else {
        const statuses = { [freshToken]: "red" };
        db.prepare(`
          INSERT INTO token_states (session_id, doctor_id, date, session, token_statuses)
          VALUES (?,?,?,?,?)
        `).run(sessionId, doctorId, date, session, JSON.stringify(statuses));
      }

      return freshToken;
    });

    let finalToken;
    try {
      finalToken = createBookingTx();
    } catch (txErr) {
      console.error("[bookings POST] transaction error:", txErr.message);
      return res.status(txErr.status || 500).json({ error: txErr.message });
    }

    // Re-fetch the booking with correct token number
    const booking = row2booking(db.prepare("SELECT * FROM bookings WHERE id=?").get(id));

    // Broadcast token state update via WebSocket
    broadcast(sessionId, { type: "token_booked", tokenNumber: finalToken, sessionId });

    console.log(`[bookings POST] created booking ${id} token ${finalToken} session ${sessionId}`);
    res.status(201).json(booking);
  }
);

// PATCH update booking status (doctor/admin)
router.patch("/:id/status", requireDoctorOrAdmin, (req, res) => {
  const { status } = req.body;
  const valid = ["confirmed", "completed", "unvisited", "cancelled"];
  if (!valid.includes(status))
    return res.status(400).json({ error: "Invalid status" });

  const booking = db.prepare("SELECT * FROM bookings WHERE id=?").get(req.params.id);
  if (!booking) return res.status(404).json({ error: "Booking not found" });

  db.prepare("UPDATE bookings SET status=? WHERE id=?").run(status, req.params.id);
  res.json(row2booking(db.prepare("SELECT * FROM bookings WHERE id=?").get(req.params.id)));
});

// GET stats (admin)
router.get("/stats/summary", requireAdmin, (req, res) => {
  const totalHospitals = db.prepare("SELECT COUNT(*) as c FROM hospitals").get().c;
  const totalDoctors   = db.prepare("SELECT COUNT(*) as c FROM doctors").get().c;
  const totalPatients  = db.prepare("SELECT COUNT(*) as c FROM users WHERE role='patient'").get().c;
  const totalBookings  = db.prepare("SELECT COUNT(*) as c FROM bookings").get().c;
  const activeSessions = db.prepare(
    "SELECT COUNT(*) as c FROM token_states WHERE is_closed=0 AND current_token IS NOT NULL"
  ).get().c;
  res.json({ totalHospitals, totalDoctors, totalPatients, totalBookings, activeSessions });
});

module.exports = router;
