require("dotenv").config()

const app = require("./src/app")
const connectToDB = require("./src/config/database")

const REQUIRED_ENV = ["MONGO_URI", "JWT_SECRET", "GOOGLE_GENAI_API_KEY"]

function assertEnv() {
    const missing = REQUIRED_ENV.filter((key) => !process.env[key])
    if (missing.length > 0) {
        console.error(`Missing required environment variables: ${missing.join(", ")}`)
        console.error("Copy .env.example to .env and fill these in before starting the server.")
        process.exit(1)
    }
}

async function startServer() {
    assertEnv()

    // A running API with no database is worse than a failed boot: every request
    // would hang or 500 with a confusing message.
    await connectToDB()

    const PORT = process.env.PORT || 5000
    const server = app.listen(PORT, () => {
        console.log(`Server is running at port ${PORT}...`)
    })

    const shutdown = (signal) => {
        console.log(`${signal} received, shutting down...`)
        server.close(() => process.exit(0))
        setTimeout(() => process.exit(1), 10000).unref()
    }

    process.on("SIGTERM", () => shutdown("SIGTERM"))
    process.on("SIGINT", () => shutdown("SIGINT"))
}

startServer().catch((error) => {
    console.error("Failed to start server:", error)
    process.exit(1)
})
