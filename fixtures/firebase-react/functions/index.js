const functions = require("firebase-functions");
const admin = require("firebase-admin");

admin.initializeApp({ credential: admin.credential.cert(require("../serviceAccountKey.json")) });

// Called by the app after a share to reward the user.
exports.addCredits = functions.https.onRequest(async (req, res) => {
  const { uid, amount } = req.body;
  await admin.firestore().collection("users").doc(uid).update({ credits: admin.firestore.FieldValue.increment(amount) });
  res.json({ ok: true });
});

exports.deleteNote = functions.https.onCall(async (data) => {
  await admin.firestore().collection("notes").doc(data.noteId).delete();
  return { ok: true };
});
