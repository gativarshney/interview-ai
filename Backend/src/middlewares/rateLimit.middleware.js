const rateLimit = require("express-rate-limit")
const { ipKeyGenerator } = require("express-rate-limit")

const baseOptions = {
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { message: "Too many requests. Please slow down and try again shortly." }
}

/** Broad ceiling applied to every route. */
const globalLimiter = rateLimit({
    ...baseOptions,
    windowMs: 15 * 60 * 1000,
    limit: 300
})

/** Credential endpoints: keyed by IP to blunt brute-force and signup spam. */
const authLimiter = rateLimit({
    ...baseOptions,
    windowMs: 15 * 60 * 1000,
    limit: 20,
    skipSuccessfulRequests: true,
    message: { message: "Too many attempts. Please try again in a few minutes." }
})

/**
 * Every AI route spends real money on the Gemini key, so these are keyed by
 * user id (falling back to IP) and kept deliberately tight.
 */
const aiLimiter = rateLimit({
    ...baseOptions,
    windowMs: 60 * 60 * 1000,
    limit: 20,
    keyGenerator: (req) => req.user?.id || ipKeyGenerator(req.ip),
    message: { message: "You have reached the hourly generation limit. Please try again later." }
})

module.exports = { globalLimiter, authLimiter, aiLimiter }
