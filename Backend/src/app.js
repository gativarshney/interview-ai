const express = require("express");

const app = express();

const cookieParser = require("cookie-parser");
const cors = require("cors")

app.use(cookieParser());

app.use(express.json());

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

const authRouter = require("./routes/auth.routes");
const interviewRouter = require("./routes/interview.routes");

app.use("/api/auth", authRouter);
app.use("/api/interview", interviewRouter);

module.exports = app;
