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
router.get("/sign-in", (req, res) => {
    
  res.render("auth/sign-in.ejs");
});
router.post("/sign-in", async (req, res) => {
  try {
    // 1. Find the user by username
    const userInDatabase = await User.findOne({ username: req.body.username });
    if (!userInDatabase) {
      return res.send("Login failed. Please try again.");
    }

    // 2. Compare submitted password to the hashed password in the database
    const validPassword = bcrypt.compareSync(
      req.body.password,
      userInDatabase.password
    );
    if (!validPassword) {
      return res.send("Login failed. Please try again.");
    }

    // 3. Success
    res.send(`Thanks for signing in ${userInDatabase.username}`);
  } catch (error) {
    console.log(error);
    res.status(500).send("Error signing in.");
  }
});
module.exports = router;
