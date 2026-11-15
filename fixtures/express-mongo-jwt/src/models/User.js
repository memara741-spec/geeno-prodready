const mongoose = require("mongoose");

const schema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "user" },
  nationalId: String,
  resetToken: String,
});

module.exports = mongoose.model("User", schema);
