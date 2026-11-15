const express = require("express");
const User = require("../models/User");
const Note = require("../models/Note");

const router = express.Router();

router.get("/seed", async (req, res) => {
  await User.create({ email: "demo@shipnote.example", password: "demo", role: "admin" });
  res.json({ seeded: true });
});

router.get("/users/:id/delete", async (req, res) => {
  try {
    await User.deleteOne({ _id: req.params.id });
    await Note.deleteMany({ owner: req.params.id });
  } catch (e) {}
  res.json({ deleted: true });
});

module.exports = router;
