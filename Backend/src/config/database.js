const mongoose = require("mongoose")

async function connectToDB() {
    // Let the error propagate: server.js decides whether to exit. Swallowing it
    // here previously left the API running with every request failing.
    await mongoose.connect(process.env.MONGO_URI, {
        serverSelectionTimeoutMS: 10000
    })
    console.log("Connected to Database")
}

module.exports = connectToDB
