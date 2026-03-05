const userModel = require("../models/user.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const tokenBlacklistModel = require("../models/blacklist.model");

/**
 * @name registerUserController
 * @description Controller to handle user registration
 * @access Public
 */

async function registerUserController(req, res) {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const isUserAlreadyExist = await userModel.findOne({
      $or: [{ email }, { username }],
    });
    if (isUserAlreadyExist) {
      if (isUserAlreadyExist.email === email) {
        return res
          .status(400)
          .json({ message: "Account already exist with this email address" });
      }
      if (isUserAlreadyExist.username === username) {
        return res.status(400).json({ message: "Username already taken" });
      }
      return res.status(400).json({ message: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new userModel({
      username,
      email,
      password: hashedPassword,
    });

    const token = jwt.sign(
      { id: newUser._id, username: newUser.username },
      process.env.JWT_SECRET,
      { expiresIn: "1d" },
    );
    res.cookie("token", token);

    await newUser.save();

    return res.status(201).json({
      message: "User registered successfully",
      token,
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
}

/**
 * @name loginUserController
 * @description Controller to handle user login
 * @access Public
 */

async function loginUserController(req, res) {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1d" },
    );
    res.cookie("token", token);

    return res.status(200).json({
      message: "User logged in successfully",
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
}

/**
 * @name logoutUserController
 * @description Controller to handle user logout
 * @access Public
 */

async function logoutUserController(req, res) {
  const token = req.cookies.token;
  if (!token) {
    return res.status(400).json({ message: "No token found in cookies" });
  }
  if (token) {
    await tokenBlacklistModel.create({ token });
  }
  res.clearCookie("token");
  return res.status(200).json({ message: "User logged out successfully" });
}

module.exports = {
  registerUserController,
  loginUserController,
  logoutUserController,
};
