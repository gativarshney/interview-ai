const multer = require("multer")

const MAX_RESUME_BYTES = 3 * 1024 * 1024 // 3MB — kept in sync with the client-side check

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: MAX_RESUME_BYTES,
        files: 1
    },
    fileFilter: (req, file, cb) => {
        // PDF only: pdf-parse is the only extractor wired up, so anything else
        // would fail deeper in the request as a confusing 500.
        const isPdf = file.mimetype === "application/pdf" && /\.pdf$/i.test(file.originalname)
        if (!isPdf) {
            return cb(new multer.MulterError("LIMIT_UNEXPECTED_FILE", "Only PDF resumes are supported."))
        }
        cb(null, true)
    }
})

module.exports = upload
module.exports.MAX_RESUME_BYTES = MAX_RESUME_BYTES
