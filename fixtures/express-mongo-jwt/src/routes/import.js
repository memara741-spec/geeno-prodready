const express = require("express");
const Note = require("../models/Note");

const router = express.Router();

// Import notes from a URL the user pastes in.
router.post("/", async (req, res) => {
  const { url } = req.body;
  const response = await fetch(url);
  const items = await response.json();
  items.forEach(async (item) => {
    await Note.create({ text: item.text, owner: req.user.id });
  });
  res.json({ imported: items.length });
});

module.exports = router;
