"use strict";
const express = require("express");
const db      = require("../db/init");
const { requireAdmin } = require("../middleware/auth");
const multer  = require("multer");
const path    = require("path");
const fs      = require("fs");

const router = express.Router();

const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || "./uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename:    (_req, file, cb) => cb(null, `hospital_${Date.now()}${path.extname(file.originalname)}`),
  }),
  limits: { fileSize: (Number(process.env.MAX_FILE_SIZE_MB) || 5) * 1024 * 1024 },
  fileFilter: (_req, file, cb) =>
    file.mimetype.startsWith("image/") ? cb(null, true) : cb(new Error("Images only")),
});

function buildPhotoUrl(req, rel) {
  if (!rel) return null;
  if (rel.startsWith("http")) return rel;
  const proto = req.headers["x-forwarded-proto"] || req.protocol || "https";
  const host  = req.headers["x-forwarded-host"] || req.headers.host || "";
  return `${proto}://${host}${rel}`;
}

function row2hospital(r, req) {
  if (!r) return null;
  const doctorCount = db.prepare("SELECT COUNT(*) as c FROM doctors WHERE hospital_id=?").get(r.id).c;
  return {
    id: r.id, name: r.name, area: r.area, address: r.address || "",
    phone: r.phone || "", rating: r.rating, gradient: r.gradient,
    photoUrl: r.photo_url ? buildPhotoUrl(req, r.photo_url) : null,
    doctorCount,
  };
}

// ── GET all ───────────────────────────────────────────────────────────────────
router.get("/", (req, res) => {
  try {
    const rows = db.prepare("SELECT * FROM hospitals ORDER BY name ASC").all();
    res.json(rows.map(r => row2hospital(r, req)));
  } catch (err) {
    console.error("[hospitals GET /]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET single ────────────────────────────────────────────────────────────────
router.get("/:id", (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Hospital not found" });
    res.json(row2hospital(row, req));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST create ───────────────────────────────────────────────────────────────
router.post("/", requireAdmin, (req, res) => {
  try {
    const { name, area, address = "", phone = "", gradient = "from-slate-400 to-slate-600" } = req.body;
    if (!name || !area) return res.status(400).json({ error: "name and area are required" });

    const id = `h_${Date.now()}`;
    db.prepare(
      "INSERT INTO hospitals (id, name, area, address, phone, gradient) VALUES (?,?,?,?,?,?)"
    ).run(id, name, area, address, phone, gradient);

    res.status(201).json(row2hospital(db.prepare("SELECT * FROM hospitals WHERE id=?").get(id), req));
  } catch (err) {
    console.error("[hospitals POST]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── PATCH update ──────────────────────────────────────────────────────────────
router.patch("/:id", requireAdmin, (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Hospital not found" });

    const { name, area, address, phone } = req.body;
    db.prepare(
      "UPDATE hospitals SET name=COALESCE(?,name), area=COALESCE(?,area), address=COALESCE(?,address), phone=COALESCE(?,phone) WHERE id=?"
    ).run(name || null, area || null, address ?? null, phone ?? null, req.params.id);

    res.json(row2hospital(db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id), req));
  } catch (err) {
    console.error("[hospitals PATCH]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST upload photo ─────────────────────────────────────────────────────────
router.post("/:id/photo", requireAdmin, upload.single("photo"), (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Hospital not found" });
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const relPath = `/uploads/${req.file.filename}`;
    db.prepare("UPDATE hospitals SET photo_url=? WHERE id=?").run(relPath, req.params.id);
    res.json({ photoUrl: buildPhotoUrl(req, relPath) });
  } catch (err) {
    console.error("[hospitals photo]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE ────────────────────────────────────────────────────────────────────
router.delete("/:id", requireAdmin, (req, res) => {
  try {
    const count = db.prepare("SELECT COUNT(*) as c FROM doctors WHERE hospital_id=?").get(req.params.id).c;
    if (count > 0)
      return res.status(409).json({ error: "Cannot delete hospital with assigned doctors. Remove doctors first." });

    db.prepare("DELETE FROM hospitals WHERE id=?").run(req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error("[hospitals DELETE]", err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
