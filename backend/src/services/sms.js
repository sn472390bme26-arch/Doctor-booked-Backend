"use strict";
/**
 * sms.js — SMS OTP sender
 *
 * Supports MSG91 (recommended for India) and Twilio.
 * If neither is configured, OTPs are logged to console
 * so you can test without spending money during development.
 *
 * ENV VARS:
 *   SMS_PROVIDER    = "msg91" | "twilio" | "dev"  (default: "dev")
 *
 *   MSG91:
 *     MSG91_AUTH_KEY      = your MSG91 auth key
 *     MSG91_TEMPLATE_ID   = your MSG91 OTP template ID
 *     MSG91_SENDER_ID     = 6-char sender ID (default: DOCBKD)
 *
 *   TWILIO:
 *     TWILIO_ACCOUNT_SID  = ACxxxxxxxx
 *     TWILIO_AUTH_TOKEN   = your auth token
 *     TWILIO_FROM         = +1234567890 (your Twilio number)
 */

const PROVIDER = (process.env.SMS_PROVIDER || "dev").toLowerCase();

// ── Generate a 6-digit OTP ────────────────────────────────────────────────────
function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ── Normalise Indian phone numbers ────────────────────────────────────────────
// Accepts: 9876543210 / +919876543210 / 919876543210
// Returns: 919876543210 (without +, with country code)
function normalisePhone(phone) {
  const digits = phone.replace(/\D/g, "");
  if (digits.startsWith("91") && digits.length === 12) return digits;
  if (digits.length === 10) return `91${digits}`;
  return digits; // return as-is for international numbers
}

// ── Send via MSG91 ────────────────────────────────────────────────────────────
async function sendMsg91(phone, otp) {
  const authKey    = process.env.MSG91_AUTH_KEY;
  const templateId = process.env.MSG91_TEMPLATE_ID;
  const senderId   = process.env.MSG91_SENDER_ID || "DOCBKD";

  if (!authKey || !templateId) {
    throw new Error("MSG91_AUTH_KEY and MSG91_TEMPLATE_ID must be set in environment variables.");
  }

  const normalised = normalisePhone(phone);

  const res = await fetch("https://control.msg91.com/api/v5/otp", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "authkey": authKey,
    },
    body: JSON.stringify({
      template_id: templateId,
      mobile: normalised,
      authkey: authKey,
      otp,
    }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.type === "error") {
    throw new Error(data.message || `MSG91 error: ${res.status}`);
  }

  console.log(`[SMS/MSG91] OTP sent to ${normalised}`);
}

// ── Send via Twilio ───────────────────────────────────────────────────────────
async function sendTwilio(phone, otp) {
  const sid   = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from  = process.env.TWILIO_FROM;

  if (!sid || !token || !from) {
    throw new Error("TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM must be set.");
  }

  const to = phone.startsWith("+") ? phone : `+${normalisePhone(phone)}`;
  const body = `Your Doctor Booked verification code is: ${otp}. Valid for 10 minutes. Do not share this code.`;

  const params = new URLSearchParams({ To: to, From: from, Body: body });
  const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Authorization": "Basic " + Buffer.from(`${sid}:${token}`).toString("base64"),
    },
    body: params.toString(),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.status === "failed") {
    throw new Error(data.message || `Twilio error: ${res.status}`);
  }

  console.log(`[SMS/Twilio] OTP sent to ${to}`);
}

// ── Dev mode — log to console ─────────────────────────────────────────────────
function sendDev(phone, otp) {
  console.log(`\n📱 [SMS/DEV] OTP for ${phone}: ${otp}\n`);
  // In dev mode, also store OTP in process so it can be returned in response
  // NEVER do this in production
}

// ── Main export ───────────────────────────────────────────────────────────────
async function sendOTP(phone, otp) {
  switch (PROVIDER) {
    case "msg91":   return await sendMsg91(phone, otp);
    case "twilio":  return await sendTwilio(phone, otp);
    case "dev":
    default:
      sendDev(phone, otp);
      return; // no network call in dev mode
  }
}

// Returns true if running in dev mode (OTP shown in response for testing)
function isDevMode() {
  return PROVIDER === "dev";
}

module.exports = { sendOTP, generateOTP, normalisePhone, isDevMode };
