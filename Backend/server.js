require("dotenv").config()

const app = require("./src/app")
const connectToDB = require("./src/config/database")

async function startServer() {
    try {
        await connectToDB()
    } catch (error) {
        console.error("Database connection failed:", error)
    }

    const PORT = process.env.PORT || 5000
    app.listen(PORT, () => {
        console.log(`Server is running at port ${PORT}...`)
    })
}

startServer()
