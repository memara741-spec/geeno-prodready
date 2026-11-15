const express = require("express");
const path = require("path");
const multer = require("multer");
const { exec } = require("child_process");

const router = express.Router();

const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => cb(null, file.originalname),
});
const upload = multer({ storage });

router.post("/upload", upload.single("file"), (req, res) => {
  res.json({ path: req.file.path });
});

router.get("/download", (req, res) => {
  res.sendFile(path.join(__dirname, "../../uploads", req.query.name));
});

router.post("/convert", (req, res) => {
  exec(`convert uploads/${req.body.file} uploads/${req.body.file}.pdf`, (err) => {
    if (err) return res.status(500).json({ error: String(err) });
    res.json({ ok: true });
  });
});

module.exports = router;
