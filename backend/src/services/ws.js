"use strict";
const { WebSocketServer } = require("ws");

// sessionId → Set of WebSocket clients
const rooms = new Map();

function setupWebSocket(server) {
  const wss = new WebSocketServer({ server, path: "/ws" });

  wss.on("connection", (ws, req) => {
    // Clients connect with ?session=SESSION_ID
    const url = new URL(req.url, "http://localhost");
    const sessionId = url.searchParams.get("session");
    if (!sessionId) { ws.close(); return; }

    if (!rooms.has(sessionId)) rooms.set(sessionId, new Set());
    rooms.get(sessionId).add(ws);

    ws.on("close", () => {
      const room = rooms.get(sessionId);
      if (room) {
        room.delete(ws);
        if (room.size === 0) rooms.delete(sessionId);
      }
    });

    ws.on("error", () => ws.terminate());
  });

  console.log("✅  WebSocket server ready at /ws?session=SESSION_ID");
  return wss;
}

/** Broadcast a JSON message to all clients watching a session */
function broadcast(sessionId, payload) {
  const room = rooms.get(sessionId);
  if (!room || room.size === 0) return;
  const msg = JSON.stringify(payload);
  for (const client of room) {
    if (client.readyState === 1 /* OPEN */) {
      client.send(msg);
    }
  }
}

module.exports = { setupWebSocket, broadcast };
