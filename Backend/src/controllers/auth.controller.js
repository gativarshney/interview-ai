const userModel = require("../models/user.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { z } = require("zod");
const tokenBlacklistModel = require("../models/blacklist.model");
const { HttpError } = require("../middlewares/error.middleware");

const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 1 day

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  maxAge: TOKEN_TTL_MS
};

const registerSchema = z.object({
  username: z
    .string()
    .trim()
    .min(3, "Username must be at least 3 characters")
    .max(32, "Username must be at most 32 characters")
    .regex(/^[a-zA-Z0-9_.-]+$/, "Username may only contain letters, numbers, and . _ -"),
  email: z.string().trim().toLowerCase().email("Please enter a valid email address"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password must be at most 128 characters")
    .regex(/[a-zA-Z]/, "Password must contain at least one letter")
    .regex(/[0-9]/, "Password must contain at least one number"),
});

const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email("Please enter a valid email address"),
  password: z.string().min(1, "Password is required"),
});

function parseOrThrow(schema, payload) {
  const result = schema.safeParse(payload);
  if (result.success) return result.data;

  const issue = result.error.issues[0];
  const field = issue?.path?.[0];

  // A missing field produces Zod's raw type message ("expected string, received
  // undefined"), which is useless to a user — name the field instead.
  const message =
    issue?.code === "invalid_type" && field
      ? `${String(field)} is required.`
      : issue?.message || "Invalid input.";

  throw new HttpError(400, message);
}

function issueToken(user) {
  return jwt.sign(
    { id: user._id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "1d" },
  );
}

function toPublicUser(user) {
  return { id: user._id, username: user.username, email: user.email };
}

/**
 * @name registerUserController
 * @description Controller to handle user registration
 * @access Public
 */

async function registerUserController(req, res) {
  const { username, email, password } = parseOrThrow(registerSchema, req.body);

  const hashedPassword = await bcrypt.hash(password, 12);

  let newUser;
  try {
    // Relies on the unique indexes rather than a check-then-insert, which has a
    // race window where two concurrent signups both pass the check.
    newUser = await userModel.create({ username, email, password: hashedPassword });
  } catch (error) {
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern || {})[0];
      throw new HttpError(
        409,
        field === "username"
          ? "Username already taken"
          : "An account already exists with this email address",
      );
    }
    throw error;
  }

  res.cookie("token", issueToken(newUser), cookieOptions);

  return res.status(201).json({
    message: "User registered successfully",
    user: toPublicUser(newUser),
  });
}

/**
 * @name loginUserController
 * @description Controller to handle user login
 * @access Public
 */

async function loginUserController(req, res) {
  const { email, password } = parseOrThrow(loginSchema, req.body);

  // password is select:false on the schema, so it must be requested explicitly.
  const user = await userModel.findOne({ email }).select("+password");

  // Same message and a comparison in both branches so response content and
  // timing do not reveal whether the account exists.
  const passwordHash = user ? user.password : "$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidinv";
  const isPasswordMatch = await bcrypt.compare(password, passwordHash);

  if (!user || !isPasswordMatch) {
    throw new HttpError(401, "Invalid email or password");
  }

  res.cookie("token", issueToken(user), cookieOptions);

  return res.status(200).json({
    message: "User logged in successfully",
    user: toPublicUser(user),
  });
}

/**
 * @name logoutUserController
 * @description Controller to handle user logout
 * @access Public
 */

async function logoutUserController(req, res) {
  const token = req.cookies.token;

  if (token) {
    let expiresAt = new Date(Date.now() + TOKEN_TTL_MS);
    try {
      // Expire the blacklist row exactly when the token itself would, so the
      // TTL index can reclaim it as soon as it stops mattering.
      const decoded = jwt.decode(token);
      if (decoded?.exp) expiresAt = new Date(decoded.exp * 1000);
    } catch {
      /* fall back to the default TTL */
    }
    await tokenBlacklistModel.updateOne(
      { token },
      { $setOnInsert: { token, expiresAt } },
      { upsert: true },
    );
  }

  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
  });

  // Idempotent: logging out twice is not an error worth surfacing to the user.
  return res.status(200).json({ message: "User logged out successfully" });
}

/**
 * @name getMeController
 * @description Controller to get the logged in user details
 * @access Private
 */

async function getMeController(req, res) {
  const user = await userModel.findById(req.user.id);
  if (!user) {
    throw new HttpError(404, "User not found");
  }
  return res.status(200).json({
    message: "User details fetched successfully",
    user: toPublicUser(user),
  });
}

module.exports = {
  registerUserController,
  loginUserController,
  logoutUserController,
  getMeController,
};
