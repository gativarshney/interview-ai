const {Router} = require("express")
const authController = require("../controllers/auth.controller")
const authMiddleware = require("../middlewares/auth.middleware")
const { asyncHandler } = require("../middlewares/error.middleware")
const { authLimiter } = require("../middlewares/rateLimit.middleware")

const authRouter = Router()

/**
 * @route POST /api/auth/register
 * @description Register a new user
 * @access Public
 */
authRouter.post("/register", authLimiter, asyncHandler(authController.registerUserController))

/**
 * @route POST /api/auth/login
 * @description Login user with email and password
 * @access Public
 */
authRouter.post("/login", authLimiter, asyncHandler(authController.loginUserController))

/**
 * @route GET /api/auth/logout
 * @description Clear token from user cookie and add the token in blacklist
 * @access Public
 */
authRouter.get("/logout", asyncHandler(authController.logoutUserController))

/**
 * @route GET /api/auth/get-me
 * @description Get the logged in user details
 * @access Private
 */
authRouter.get("/get-me", authMiddleware.authUser, asyncHandler(authController.getMeController))


module.exports = authRouter
