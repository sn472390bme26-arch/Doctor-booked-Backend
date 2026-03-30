"use strict";
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
require("dotenv").config();

const DB_PATH = process.env.DB_PATH || "./data/doctor_booked.db";
const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");   // allows concurrent reads during writes
db.pragma("busy_timeout = 5000");  // retry locked DB for up to 5s instead of failing instantly
db.pragma("synchronous = NORMAL"); // safe with WAL, faster than FULL
db.pragma("foreign_keys = ON");
db.pragma("cache_size = -32000");  // 32MB page cache

db.exec(`
  -- ─────────────────────────────────────────────
  --  USERS  (patients + admin; doctors have their
  --          own table but also a user row)
  -- ─────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE,
    name        TEXT,
    password    TEXT,           -- bcrypt hash
    role        TEXT NOT NULL CHECK(role IN ('patient','doctor','admin')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ─────────────────────────────────────────────
  --  HOSPITALS
  -- ─────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS hospitals (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    area        TEXT NOT NULL,
    address     TEXT,
    phone       TEXT,
    rating      REAL NOT NULL DEFAULT 4.0,
    gradient    TEXT NOT NULL DEFAULT 'from-slate-400 to-slate-600',
    photo_url   TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ─────────────────────────────────────────────
  --  DOCTORS
  -- ─────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS doctors (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT REFERENCES users(id) ON DELETE SET NULL,
    hospital_id         TEXT NOT NULL REFERENCES hospitals(id) ON DELETE CASCADE,
    code                TEXT UNIQUE NOT NULL,
    name                TEXT NOT NULL,
    specialty           TEXT NOT NULL,
    phone               TEXT,
    bio                 TEXT,
    photo               TEXT,
    price               REAL NOT NULL DEFAULT 10,
    consultation_fee    REAL NOT NULL DEFAULT 10,
    tokens_per_session  INTEGER NOT NULL DEFAULT 20,
    sessions            TEXT NOT NULL DEFAULT 'morning,afternoon',
    session_timings     TEXT,           -- JSON
    is_available        INTEGER NOT NULL DEFAULT 1,
    years_of_experience TEXT,
    education           TEXT,
    languages           TEXT,           -- JSON array
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ─────────────────────────────────────────────
  --  BOOKINGS
  -- ─────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS bookings (
    id              TEXT PRIMARY KEY,
    patient_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    patient_name    TEXT NOT NULL,
    doctor_id       TEXT NOT NULL REFERENCES doctors(id) ON DELETE CASCADE,
    doctor_name     TEXT NOT NULL,
    hospital_name   TEXT NOT NULL,
    date            TEXT NOT NULL,    -- YYYY-MM-DD
    session         TEXT NOT NULL,    -- morning | afternoon | evening
    token_number    INTEGER NOT NULL,
    session_id      TEXT NOT NULL,    -- doctorId_date_session
    payment_done    INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'confirmed'
                    CHECK(status IN ('confirmed','completed','unvisited','cancelled')),
    phone           TEXT,
    complaint       TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ─────────────────────────────────────────────
  --  TOKEN STATES  (one row per session)
  -- ─────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS token_states (
    session_id        TEXT PRIMARY KEY,
    doctor_id         TEXT NOT NULL,
    date              TEXT NOT NULL,
    session           TEXT NOT NULL,
    token_statuses    TEXT NOT NULL DEFAULT '{}',   -- JSON
    priority_slots    TEXT NOT NULL DEFAULT '{}',   -- JSON
    current_token     INTEGER,
    next_token        INTEGER,
    is_closed         INTEGER NOT NULL DEFAULT 0,
    cancelled_keys    TEXT NOT NULL DEFAULT '[]',   -- JSON array
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ─────────────────────────────────────────────
  --  INDEXES
  -- ─────────────────────────────────────────────
  CREATE INDEX IF NOT EXISTS idx_bookings_patient    ON bookings(patient_id);
  CREATE INDEX IF NOT EXISTS idx_bookings_session    ON bookings(session_id);
  CREATE INDEX IF NOT EXISTS idx_bookings_doctor     ON bookings(doctor_id);
  CREATE INDEX IF NOT EXISTS idx_doctors_hospital    ON doctors(hospital_id);
  CREATE INDEX IF NOT EXISTS idx_token_states_doctor ON token_states(doctor_id);
`);

console.log("✅  Database initialised at", path.resolve(DB_PATH));
module.exports = db;
