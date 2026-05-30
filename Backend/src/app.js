const express = require("express");

const app = express();

const cookieParser = require("cookie-parser");
const cors = require("cors")

app.use(cookieParser());

app.use(express.json());

const rawFrontendUrl = (process.env.FRONTEND_URL || "http://localhost:5173").trim();
const frontendUrl = rawFrontendUrl.replace(/\/+$/, "");

app.use(cors({
    origin: frontendUrl,
    credentials: true
}));

const authRouter = require("./routes/auth.routes");
const interviewRouter = require("./routes/interview.routes");

app.use("/api/auth", authRouter);
app.use("/api/interview", interviewRouter);

module.exports = app;
