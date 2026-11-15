const express = require("express");
const User = require("../models/User");
const Note = require("../models/Note");

const router = express.Router();

router.get("/", async (req, res) => {
  const users = await User.find({});
  res.json(users);
});

router.put("/:id", async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(user);
});

router.get("/:id/notes", async (req, res) => {
  const notes = await Note.find({ owner: req.params.id });
  const result = [];
  for (const note of notes) {
    const driver = await User.findById(note.driver);
    result.push({ text: note.text, driver: driver && driver.email });
  }
  res.json(result);
});

module.exports = router;
