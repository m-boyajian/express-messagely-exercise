const jwt = require("jsonwebtoken");
const Router = require("express").Router;
const router = new Router();
const { SECRET_KEY, BCRYPT_WORK_FACTOR } = require("../config");
const User = require("../models/user");
const ExpressError = require("../expressError")
const bcrypt = require('bcrypt');

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async function (req, res, next) {
  try {
    const { username, password } = req.body;
    const result = await User.authenticate(username, password);  // Use User.authenticate
    if (result) {
      // Update last login timestamp
      await User.updateLoginTimestamp(username);

      // Generate a JWT token
      const token = jwt.sign({ username }, SECRET_KEY);

      return res.json({ token });
    } else {
      throw new ExpressError("Invalid user/password", 400);
    }
  } catch (err) {
    return next(err);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async function (req, res, next) {
  try {
    const { username, password, first_name, last_name, phone } = req.body;
    console.log('BCRYPT_WORK_FACTOR:', BCRYPT_WORK_FACTOR);
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const newUser = await User.register({
      username,
      password: hashedPassword,
      first_name,
      last_name,
      phone
    });

    // Generate a JWT token
    const token = jwt.sign({ username: newUser.username }, SECRET_KEY);

    return res.json({ token });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
