"use strict";
const express = require("express");
const { body, validationResult } = require("express-validator");
const { v4: uuid } = require("../utils/id");
const db = require("../db/init");
const { requireAuth, requireAdmin } = require("../middleware/auth");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const router = express.Router();

const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || "./uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `hospital_${Date.now()}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: (Number(process.env.MAX_FILE_SIZE_MB) || 5) * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Only image files are allowed"));
  },
});

function row2hospital(r) {
  if (!r) return null;
  const doctorCount = db.prepare("SELECT COUNT(*) as c FROM doctors WHERE hospital_id=?").get(r.id).c;
  return {
    id: r.id,
    name: r.name,
    area: r.area,
    address: r.address || "",
    phone: r.phone || "",
    rating: r.rating,
    gradient: r.gradient,
    photoUrl: r.photo_url || null,
    doctorCount,
  };
}

// GET all hospitals (public)
router.get("/", (req, res) => {
  const rows = db.prepare("SELECT * FROM hospitals ORDER BY name ASC").all();
  res.json(rows.map(row2hospital));
});

// GET single hospital
router.get("/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Hospital not found" });
  res.json(row2hospital(row));
});

// POST create hospital (admin only)
router.post(
  "/",
  requireAdmin,
  [
    body("name").trim().notEmpty().withMessage("Name is required"),
    body("area").trim().notEmpty().withMessage("Area is required"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array()[0].msg });

    const { name, area, address = "", phone = "", gradient = "from-slate-400 to-slate-600" } = req.body;
    const id = `h_${Date.now()}`;
    db.prepare(
      "INSERT INTO hospitals (id, name, area, address, phone, gradient) VALUES (?,?,?,?,?,?)"
    ).run(id, name, area, address, phone, gradient);

    res.status(201).json(row2hospital(db.prepare("SELECT * FROM hospitals WHERE id=?").get(id)));
  }
);

// PATCH update hospital (admin only)
router.patch(
  "/:id",
  requireAdmin,
  (req, res) => {
    const row = db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Hospital not found" });

    const { name, area, address, phone } = req.body;
    db.prepare(
      "UPDATE hospitals SET name=COALESCE(?,name), area=COALESCE(?,area), address=COALESCE(?,address), phone=COALESCE(?,phone) WHERE id=?"
    ).run(name || null, area || null, address ?? null, phone ?? null, req.params.id);

    res.json(row2hospital(db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id)));
  }
);

// POST upload hospital photo (admin only)
router.post("/:id/photo", requireAdmin, upload.single("photo"), (req, res) => {
  const row = db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Hospital not found" });
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const photoUrl = `/uploads/${req.file.filename}`;
  db.prepare("UPDATE hospitals SET photo_url=? WHERE id=?").run(photoUrl, req.params.id);
  res.json({ photoUrl });
});

// DELETE hospital (admin only)
router.delete("/:id", requireAdmin, (req, res) => {
  const doctorCount = db.prepare("SELECT COUNT(*) as c FROM doctors WHERE hospital_id=?").get(req.params.id).c;
  if (doctorCount > 0)
    return res.status(409).json({ error: "Cannot delete hospital with assigned doctors. Remove doctors first." });

  db.prepare("DELETE FROM hospitals WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

module.exports = router;
