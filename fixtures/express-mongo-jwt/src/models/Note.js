const mongoose = require("mongoose");

module.exports = mongoose.model("Note", new mongoose.Schema({ text: String, owner: String, driver: String }));
