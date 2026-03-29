"use strict";
const express = require("express");
const db = require("../db/init");
const { requireAuth, requireDoctorOrAdmin } = require("../middleware/auth");
const { broadcast } = require("../services/ws");

const router = express.Router();

function getState(sessionId) {
  return db.prepare("SELECT * FROM token_states WHERE session_id=?").get(sessionId);
}

function parseState(row) {
  if (!row) return null;
  return {
    sessionId: row.session_id,
    doctorId: row.doctor_id,
    date: row.date,
    session: row.session,
    tokenStatuses: JSON.parse(row.token_statuses || "{}"),
    prioritySlots: JSON.parse(row.priority_slots || "{}"),
    currentToken: row.current_token,
    nextToken: row.next_token,
    isClosed: row.is_closed === 1,
    cancelledSessions: JSON.parse(row.cancelled_keys || "[]"),
  };
}

function saveState(sessionId, statuses, prioritySlots, currentToken, nextToken, isClosed) {
  db.prepare(`
    UPDATE token_states SET
      token_statuses=?, priority_slots=?, current_token=?, next_token=?, is_closed=?,
      updated_at=datetime('now')
    WHERE session_id=?
  `).run(
    JSON.stringify(statuses),
    JSON.stringify(prioritySlots),
    currentToken ?? null,
    nextToken ?? null,
    isClosed ? 1 : 0,
    sessionId
  );
}

function broadcastState(sessionId) {
  const state = parseState(getState(sessionId));
  if (state) broadcast(sessionId, { type: "state_update", state });
}

// GET token state for a session (public — patients need this for live tracking)
router.get("/:sessionId", (req, res) => {
  const row = getState(req.params.sessionId);
  if (!row) return res.json(null);
  res.json(parseState(row));
});

// POST regulate — doctor clicks a token to mark it as "currently being seen"
router.post("/:sessionId/regulate", requireDoctorOrAdmin, (req, res) => {
  const { clickedToken } = req.body;
  if (!Number.isInteger(clickedToken))
    return res.status(400).json({ error: "clickedToken must be an integer" });

  const row = getState(req.params.sessionId);
  if (!row) return res.status(404).json({ error: "Session not found" });

  const state = parseState(row);
  const statuses = { ...state.tokenStatuses };
  let { currentToken, nextToken } = state;

  // Mark previous current as green (completed)
  if (currentToken !== null && currentToken !== clickedToken) {
    statuses[currentToken] = "green";
  }

  // Set clicked to orange (ongoing)
  statuses[clickedToken] = "orange";
  currentToken = clickedToken;

  // Reset old yellow back to red
  if (nextToken !== null && statuses[nextToken] === "yellow") {
    statuses[nextToken] = "red";
  }

  // Pick next red token and mark yellow
  const redTokens = Object.entries(statuses)
    .filter(([n, s]) => s === "red" && Number(n) !== clickedToken)
    .map(([n]) => Number(n))
    .sort((a, b) => a - b);

  const nextRed = redTokens[0] ?? null;
  if (nextRed !== null) statuses[nextRed] = "yellow";
  nextToken = nextRed;

  saveState(req.params.sessionId, statuses, state.prioritySlots, currentToken, nextToken, state.isClosed);
  broadcastState(req.params.sessionId);
  res.json(parseState(getState(req.params.sessionId)));
});

// POST complete — current token done
router.post("/:sessionId/complete", requireDoctorOrAdmin, (req, res) => {
  const row = getState(req.params.sessionId);
  if (!row) return res.status(404).json({ error: "Session not found" });

  const state = parseState(row);
  const statuses = { ...state.tokenStatuses };
  let { currentToken, nextToken } = state;

  if (currentToken !== null) statuses[currentToken] = "green";

  // Auto-pick next if none queued
  let newNextToken = nextToken;
  if (newNextToken === null) {
    const reds = Object.entries(statuses)
      .filter(([, s]) => s === "red")
      .map(([n]) => Number(n))
      .sort((a, b) => a - b);
    if (reds[0] !== undefined) {
      statuses[reds[0]] = "yellow";
      newNextToken = reds[0];
    }
  }

  saveState(req.params.sessionId, statuses, state.prioritySlots, null, newNextToken, state.isClosed);
  broadcastState(req.params.sessionId);
  res.json(parseState(getState(req.params.sessionId)));
});

// POST skip — skip current token (mark unvisited)
router.post("/:sessionId/skip", requireDoctorOrAdmin, (req, res) => {
  const row = getState(req.params.sessionId);
  if (!row) return res.status(404).json({ error: "Session not found" });

  const state = parseState(row);
  const statuses = { ...state.tokenStatuses };
  let { currentToken, nextToken } = state;

  if (currentToken !== null) statuses[currentToken] = "unvisited";

  let newNextToken = nextToken;
  if (newNextToken === null) {
    const reds = Object.entries(statuses)
      .filter(([, s]) => s === "red")
      .map(([n]) => Number(n))
      .sort((a, b) => a - b);
    if (reds[0] !== undefined) {
      statuses[reds[0]] = "yellow";
      newNextToken = reds[0];
    }
  }

  saveState(req.params.sessionId, statuses, state.prioritySlots, null, newNextToken, state.isClosed);
  broadcastState(req.params.sessionId);
  res.json(parseState(getState(req.params.sessionId)));
});

// POST complete a previously skipped token
router.post("/:sessionId/complete-skipped", requireDoctorOrAdmin, (req, res) => {
  const { tokenNum } = req.body;
  const row = getState(req.params.sessionId);
  if (!row) return res.status(404).json({ error: "Session not found" });

  const state = parseState(row);
  const statuses = { ...state.tokenStatuses };
  if (statuses[tokenNum] === "unvisited") statuses[tokenNum] = "green";

  saveState(req.params.sessionId, statuses, state.prioritySlots, state.currentToken, state.nextToken, state.isClosed);
  broadcastState(req.params.sessionId);
  res.json(parseState(getState(req.params.sessionId)));
});

// POST close session
router.post("/:sessionId/close", requireDoctorOrAdmin, (req, res) => {
  const row = getState(req.params.sessionId);
  if (!row) return res.status(404).json({ error: "Session not found" });

  const state = parseState(row);
  const statuses = { ...state.tokenStatuses };
  for (const [n, s] of Object.entries(statuses)) {
    if (s === "red" || s === "yellow") statuses[Number(n)] = "unvisited";
  }

  saveState(req.params.sessionId, statuses, state.prioritySlots, null, null, true);

  // Mark remaining confirmed bookings as unvisited
  db.prepare(
    "UPDATE bookings SET status='unvisited' WHERE session_id=? AND status='confirmed'"
  ).run(req.params.sessionId);

  broadcastState(req.params.sessionId);
  res.json(parseState(getState(req.params.sessionId)));
});

// POST set priority slot
router.post("/:sessionId/priority-slot", requireDoctorOrAdmin, (req, res) => {
  const { slotIndex, slot } = req.body;
  const row = getState(req.params.sessionId);
  if (!row) return res.status(404).json({ error: "Session not found" });

  const state = parseState(row);
  const prioritySlots = { ...state.prioritySlots, [slotIndex]: slot };

  saveState(req.params.sessionId, state.tokenStatuses, prioritySlots, state.currentToken, state.nextToken, state.isClosed);
  broadcastState(req.params.sessionId);
  res.json(parseState(getState(req.params.sessionId)));
});

// POST cancel a future session
router.post("/cancel-session", requireDoctorOrAdmin, (req, res) => {
  const { doctorId, date, session } = req.body;
  const key = `${doctorId}_${date}_${session}`;
  const SENTINEL = "__cancelled__";

  let row = getState(SENTINEL);
  if (!row) {
    db.prepare(
      "INSERT OR IGNORE INTO token_states (session_id, doctor_id, date, session, cancelled_keys) VALUES (?,?,?,?,?)"
    ).run(SENTINEL, "", "", "morning", JSON.stringify([key]));
  } else {
    const keys = JSON.parse(row.cancelled_keys || "[]");
    if (!keys.includes(key)) keys.push(key);
    db.prepare("UPDATE token_states SET cancelled_keys=? WHERE session_id=?")
      .run(JSON.stringify(keys), SENTINEL);
  }
  res.json({ success: true, cancelledKey: key });
});

// GET cancelled sessions list
router.get("/cancelled/list", (req, res) => {
  const row = getState("__cancelled__");
  if (!row) return res.json([]);
  res.json(JSON.parse(row.cancelled_keys || "[]"));
});

module.exports = router;
