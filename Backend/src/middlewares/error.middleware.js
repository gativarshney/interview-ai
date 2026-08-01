const multer = require("multer")

/**
 * Wraps an async route handler so a rejected promise is forwarded to the
 * error handler instead of becoming an unhandled rejection.
 */
function asyncHandler(handler) {
    return function (req, res, next) {
        Promise.resolve(handler(req, res, next)).catch(next)
    }
}

/**
 * Thrown deliberately by controllers to return a specific status code.
 */
class HttpError extends Error {
    constructor(status, message) {
        super(message)
        this.status = status
    }
}

function notFoundHandler(req, res) {
    res.status(404).json({ message: `Route ${req.method} ${req.originalUrl} not found` })
}

// eslint-disable-next-line no-unused-vars
function errorHandler(error, req, res, next) {
    if (res.headersSent) {
        return next(error)
    }

    let status = error.status || 500
    let message = error.message || "Internal Server Error"

    if (error instanceof multer.MulterError) {
        status = 400
        message = error.code === "LIMIT_FILE_SIZE"
            ? "Resume file is too large. Maximum size is 3MB."
            : `Upload failed: ${error.message}`
    } else if (error.name === "CastError") {
        status = 400
        message = "Invalid identifier."
    } else if (error.name === "ValidationError") {
        status = 400
        message = Object.values(error.errors || {}).map((e) => e.message).join(", ") || "Validation failed."
    } else if (error.code === 11000) {
        status = 409
        message = "That record already exists."
    }

    // Never leak internal failure details to the client.
    if (status >= 500) {
        console.error(`[error] ${req.method} ${req.originalUrl}`, error)
        message = "Something went wrong on our end. Please try again."
    }

    res.status(status).json({ message })
}

module.exports = { asyncHandler, HttpError, notFoundHandler, errorHandler }
