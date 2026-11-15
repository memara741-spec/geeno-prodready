const express = require("express");
const Note = require("../models/Note");

const router = express.Router();

router.post("/github", async (req, res) => {
  const event = req.body;
  if (event.action === "opened") {
    await Note.create({ text: `Issue opened: ${event.issue.title}`, owner: "system" });
  }
  res.sendStatus(200);
});

module.exports = router;
