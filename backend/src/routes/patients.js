"use strict";
const express = require("express");
const db = require("../db/init");
const { requireAdmin } = require("../middleware/auth");

const router = express.Router();

// GET all patients (admin)
router.get("/", requireAdmin, (req, res) => {
  const rows = db.prepare(
    "SELECT id, name, email, created_at FROM users WHERE role='patient' ORDER BY created_at DESC"
  ).all();
  res.json(rows.map(r => ({
    id: r.id,
    name: r.name,
    email: r.email || "",
    createdAt: r.created_at,
  })));
});

module.exports = router;
