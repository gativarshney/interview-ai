const express = require("express");

const app = express();

const cookieParser = require("cookie-parser");
const cors = require("cors")
const helmet = require("helmet")

const { globalLimiter } = require("./middlewares/rateLimit.middleware")
const { notFoundHandler, errorHandler } = require("./middlewares/error.middleware")

// Render puts us behind a proxy; without this req.ip is the proxy's address and
// every user would share a single rate-limit bucket.
app.set("trust proxy", 1)

app.use(helmet())

app.use(cookieParser());

app.use(express.json({ limit: "100kb" }));

const rawFrontendUrl = (process.env.FRONTEND_URL || "http://localhost:5173").trim();
const normalizedFrontendUrl = rawFrontendUrl.replace(/\/+$/, "");

const allowedOrigins = [
    normalizedFrontendUrl,
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:3000"
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes(origin.replace(/\/+$/, ""))) {
            return callback(null, true);
        } else {
            return callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(globalLimiter)

const authRouter = require("./routes/auth.routes");
const interviewRouter = require("./routes/interview.routes");

/**
 * Cheap liveness probe. Also usable as a warm-up ping so the free-tier
 * instance is not cold when someone opens the demo link.
 */
app.get("/health", (req, res) => {
    res.status(200).json({
        status: "ok",
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    })
})

app.use("/api/auth", authRouter);
app.use("/api/interview", interviewRouter);

app.use(notFoundHandler)
app.use(errorHandler)

module.exports = app;
