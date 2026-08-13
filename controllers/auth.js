const bcrypt = require("bcrypt");
const User = require("../models/user.js");
const express = require("express");
const router = express.Router();
const SALT_ROUNDS=10;
router.get("/sign-up", (req, res) => {
    
  res.render("auth/sign-up.ejs");
});
router.post("/sign-up", async (req, res) => {
  try {
    // 1. Check if username already exists
    const userInDatabase = await User.findOne({ username: req.body.username });
    if (userInDatabase) {
      return res.send("Username already taken.");
    }

    // 2. Check password and confirmPassword match
    if (req.body.password !== req.body.confirmPassword) {
      return res.send("Password and Confirm Password must match");
    }

    // 3. Hash the password before saving
    const hashedPassword = bcrypt.hashSync(req.body.password, SALT_ROUNDS);
    req.body.password = hashedPassword;
      delete req.body.confirmPassword;
    // 4. Create the user
    const user = await User.create(req.body);
    res.send(`Thanks for signing up ${user.username}`);
  } catch (error) {
    console.log(error);
    res.status(500).send("Error signing up.");
  }
});

module.exports = router;
