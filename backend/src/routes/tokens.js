"use strict";
const express = require("express");
const db      = require("../db/init");
const { requireDoctorOrAdmin } = require("../middleware/auth");
const { broadcast } = require("../services/ws");

const router = express.Router();
const SENTINEL = "__cancelled__";

// ── Helpers ───────────────────────────────────────────────────────────────────
function getState(sessionId) {
  return db.stmts.getTokenState.get(sessionId);
}

function parseState(row) {
  if (!row) return null;
  return {
    sessionId:        row.session_id,
    doctorId:         row.doctor_id,
    date:             row.date,
    session:          row.session,
    tokenStatuses:    JSON.parse(row.token_statuses  || "{}"),
    prioritySlots:    JSON.parse(row.priority_slots  || "{}"),
    currentToken:     row.current_token,
    nextToken:        row.next_token,
    isClosed:         row.is_closed === 1,
    cancelledSessions: JSON.parse(row.cancelled_keys || "[]"),
  };
}

// Single prepared statement update — avoids re-parsing SQL on every token click
function saveState(sid, statuses, slots, current, next, closed) {
  db.stmts.updateTokenState.run(
    JSON.stringify(statuses),
    JSON.stringify(slots),
    current ?? null,
    next    ?? null,
    closed ? 1 : 0,
    sid
  );
}

function broadcastState(sessionId) {
  const state = parseState(getState(sessionId));
  if (state) broadcast(sessionId, { type: "state_update", state });
}

// Wrap every write in a transaction + error handler
function withTx(sessionId, res, fn) {
  try {
    const row = getState(sessionId);
    if (!row) return res.status(404).json({ error: "Session not found" });
    db.transaction(() => fn(parseState(row)))();
    broadcastState(sessionId);
    res.json(parseState(getState(sessionId)));
  } catch (err) {
    console.error(`[tokens] error session=${sessionId}:`, err.message);
    res.status(500).json({ error: err.message });
  }
}

// ── GET token state ───────────────────────────────────────────────────────────
router.get("/:sessionId", (req, res) => {
  try {
    const row = getState(req.params.sessionId);
    res.json(row ? parseState(row) : null);
  } catch (err) {
    console.error("[tokens GET]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST regulate ─────────────────────────────────────────────────────────────
router.post("/:sessionId/regulate", requireDoctorOrAdmin, (req, res) => {
  const clicked = Number(req.body.clickedToken);
  if (!Number.isInteger(clicked))
    return res.status(400).json({ error: "clickedToken must be an integer" });

  withTx(req.params.sessionId, res, (state) => {
    const statuses = { ...state.tokenStatuses };
    let { currentToken, nextToken } = state;

    if (currentToken !== null && currentToken !== clicked)
      statuses[currentToken] = "green";

    statuses[clicked] = "orange";
    currentToken = clicked;

    if (nextToken !== null && statuses[nextToken] === "yellow")
      statuses[nextToken] = "red";

    const reds = Object.entries(statuses)
      .filter(([n, s]) => s === "red" && Number(n) !== clicked)
      .map(([n]) => Number(n)).sort((a, b) => a - b);

    const nextRed = reds[0] ?? null;
    if (nextRed !== null) statuses[nextRed] = "yellow";
    nextToken = nextRed;

    saveState(req.params.sessionId, statuses, state.prioritySlots, currentToken, nextToken, state.isClosed);
  });
});

// ── POST complete ─────────────────────────────────────────────────────────────
router.post("/:sessionId/complete", requireDoctorOrAdmin, (req, res) => {
  withTx(req.params.sessionId, res, (state) => {
    const statuses = { ...state.tokenStatuses };
    if (state.currentToken !== null) statuses[state.currentToken] = "green";

    let next = state.nextToken;
    if (next === null) {
      const reds = Object.entries(statuses)
        .filter(([, s]) => s === "red").map(([n]) => Number(n)).sort((a, b) => a - b);
      if (reds[0] !== undefined) { statuses[reds[0]] = "yellow"; next = reds[0]; }
    }
    saveState(req.params.sessionId, statuses, state.prioritySlots, null, next, state.isClosed);
  });
});

// ── POST skip ─────────────────────────────────────────────────────────────────
router.post("/:sessionId/skip", requireDoctorOrAdmin, (req, res) => {
  withTx(req.params.sessionId, res, (state) => {
    const statuses = { ...state.tokenStatuses };
    if (state.currentToken !== null) statuses[state.currentToken] = "unvisited";

    let next = state.nextToken;
    if (next === null) {
      const reds = Object.entries(statuses)
        .filter(([, s]) => s === "red").map(([n]) => Number(n)).sort((a, b) => a - b);
      if (reds[0] !== undefined) { statuses[reds[0]] = "yellow"; next = reds[0]; }
    }
    saveState(req.params.sessionId, statuses, state.prioritySlots, null, next, state.isClosed);
  });
});

// ── POST complete-skipped ─────────────────────────────────────────────────────
router.post("/:sessionId/complete-skipped", requireDoctorOrAdmin, (req, res) => {
  const tokenNum = Number(req.body.tokenNum);
  withTx(req.params.sessionId, res, (state) => {
    const statuses = { ...state.tokenStatuses };
    if (statuses[tokenNum] === "unvisited") statuses[tokenNum] = "green";
    saveState(req.params.sessionId, statuses, state.prioritySlots, state.currentToken, state.nextToken, state.isClosed);
  });
});

// ── POST close session ────────────────────────────────────────────────────────
router.post("/:sessionId/close", requireDoctorOrAdmin, (req, res) => {
  withTx(req.params.sessionId, res, (state) => {
    const statuses = { ...state.tokenStatuses };
    for (const [n, s] of Object.entries(statuses))
      if (s === "red" || s === "yellow") statuses[Number(n)] = "unvisited";

    saveState(req.params.sessionId, statuses, state.prioritySlots, null, null, true);
    db.prepare("UPDATE bookings SET status='unvisited' WHERE session_id=? AND status='confirmed'")
      .run(req.params.sessionId);
  });
});

// ── POST priority-slot ────────────────────────────────────────────────────────
router.post("/:sessionId/priority-slot", requireDoctorOrAdmin, (req, res) => {
  const { slotIndex, slot } = req.body;
  withTx(req.params.sessionId, res, (state) => {
    const slots = { ...state.prioritySlots, [slotIndex]: slot };
    saveState(req.params.sessionId, state.tokenStatuses, slots, state.currentToken, state.nextToken, state.isClosed);
  });
});

// ── POST cancel-session ───────────────────────────────────────────────────────
router.post("/cancel-session", requireDoctorOrAdmin, (req, res) => {
  try {
    const { doctorId, date, session } = req.body;
    const key = `${doctorId}_${date}_${session}`;

    db.transaction(() => {
      const row = getState(SENTINEL);
      if (!row) {
        db.prepare(
          "INSERT OR IGNORE INTO token_states (session_id, doctor_id, date, session, cancelled_keys) VALUES (?,?,?,?,?)"
        ).run(SENTINEL, "", "", "morning", JSON.stringify([key]));
      } else {
        const keys = JSON.parse(row.cancelled_keys || "[]");
        if (!keys.includes(key)) {
          keys.push(key);
          db.prepare("UPDATE token_states SET cancelled_keys=? WHERE session_id=?")
            .run(JSON.stringify(keys), SENTINEL);
        }
      }
    })();

    res.json({ success: true, cancelledKey: key });
  } catch (err) {
    console.error("[tokens cancel-session]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET cancelled list ────────────────────────────────────────────────────────
router.get("/cancelled/list", (req, res) => {
  try {
    const row = getState(SENTINEL);
    res.json(row ? JSON.parse(row.cancelled_keys || "[]") : []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
