"use strict";
/**
 * firebase-admin.js — Firebase Admin SDK initialisation
 *
 * Used to verify Firebase ID tokens sent from the frontend after
 * phone OTP verification. The frontend verifies the OTP with Firebase,
 * gets an ID token, and sends it to this backend. We verify it here.
 *
 * ENV VAR required on Railway:
 *   FIREBASE_SERVICE_ACCOUNT  — JSON string of the service account key
 *                               (copy the entire contents of the downloaded JSON file)
 */
const admin = require("firebase-admin");

let _initialized = false;

function getFirebaseAdmin() {
  if (_initialized) return admin;

  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!serviceAccountJson) {
    console.warn("[firebase-admin] FIREBASE_SERVICE_ACCOUNT not set — phone auth disabled");
    return null;
  }

  try {
    const serviceAccount = JSON.parse(serviceAccountJson);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    _initialized = true;
    console.log("[firebase-admin] Initialized for project:", serviceAccount.project_id);
    return admin;
  } catch (err) {
    console.error("[firebase-admin] Failed to initialize:", err.message);
    return null;
  }
}

// Verify a Firebase ID token and return the decoded phone number
async function verifyFirebaseToken(idToken) {
  const fb = getFirebaseAdmin();
  if (!fb) throw new Error("Firebase is not configured on this server.");

  const decoded = await fb.auth().verifyIdToken(idToken);

  // Firebase phone auth tokens contain phone_number claim
  if (!decoded.phone_number) {
    throw new Error("This Firebase token does not contain a phone number.");
  }

  return {
    phoneNumber: decoded.phone_number, // E.164 format: +919876543210
    uid: decoded.uid,
    firebase: decoded.firebase,
  };
}

module.exports = { verifyFirebaseToken, getFirebaseAdmin };
