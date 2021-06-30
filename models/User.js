const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    min: 6,
    max: 255,
  },
  email: {
    type: String,
    required: true,
    min: 6,
    max: 255,
  },
  password: {
    type: String,
    required: true,
    min: 6,
    max: 1024,
  },
  date: {
    type: Date,
    default: Date.now,
  },
  verified: {
      type: Boolean,
      default: false
  },
  temp: {
      type: String,
      required: false,
      min: 5,
      max: 6,
  }
});

module.exports = mongoose.model("User", userSchema);