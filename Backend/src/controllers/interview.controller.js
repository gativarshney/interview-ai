const pdfParse = require("pdf-parse")
const { generateInterviewReport, generateResumePdf, evaluatePracticeAnswer, generateResumeHtml, generatePdfFromHtml } = require("../services/ai.service")
const interviewReportModel = require("../models/interviewReport.model")

/**
 * @description Controller to generate interview report based on user self description, resume and job description.
 */
function getTitleFromJobDescription(jobDescription) {
    const lines = String(jobDescription || "").split("\n").map((line) => line.trim()).filter(Boolean)
    if (lines.length === 0) return "Untitled Job"

    const firstLine = lines[0]
    const normalized = firstLine.replace(/^Position\s*[:\-]\s*/i, "").trim()
    return normalized || firstLine
}

async function generateInterViewReportController(req, res) {
    try {
        // Accept optional resume file. If present, parse PDF; otherwise use empty resume text.
        let resumeText = ""
        let resumeFilename = ""
        if (req.file && req.file.buffer) {
            const resumeContent = await (new pdfParse.PDFParse(Uint8Array.from(req.file.buffer))).getText()
            resumeText = resumeContent.text
            resumeFilename = req.file.originalname
        }

        const { selfDescription, jobDescription, title } = req.body

        // Require jobDescription and at least one of selfDescription or resume
        if (!jobDescription) {
            return res.status(400).json({ message: "jobDescription is required." })
        }

        if (!selfDescription && !resumeText) {
            return res.status(400).json({ message: "Either selfDescription or resume file is required." })
        }

        const interViewReportByAi = await generateInterviewReport({
            resume: resumeText,
            selfDescription,
            jobDescription
        })

        const interviewReport = await interviewReportModel.create({
            user: req.user.id,
            resume: resumeText,
            resumeFilename,
            selfDescription,
            jobDescription,
            title: title || interViewReportByAi.title || getTitleFromJobDescription(jobDescription),
            ...interViewReportByAi
        })

        res.status(201).json({
            message: "Interview report generated successfully.",
            interviewReport
        })
    } catch (error) {
        console.error("Error in generateInterViewReportController:", error)
        res.status(500).json({ message: "Failed to generate interview report. " + error.message })
    }
}

/**
 * @description Controller to get interview report by interviewId.
 */
async function getInterviewReportByIdController(req, res) {

    const { interviewId } = req.params

    const interviewReport = await interviewReportModel.findOne({ _id: interviewId, user: req.user.id })

    if (!interviewReport) {
        return res.status(404).json({
            message: "Interview report not found."
        })
    }

    res.status(200).json({
        message: "Interview report fetched successfully.",
        interviewReport
    })
}


/** 
 * @description Controller to get all interview reports of logged in user.
 */
async function getAllInterviewReportsController(req, res) {
    const interviewReports = await interviewReportModel.find({ user: req.user.id }).sort({ createdAt: -1 }).select("-resume -selfDescription -jobDescription -__v -technicalQuestions -behavioralQuestions -preparationPlan")

    res.status(200).json({
        message: "Interview reports fetched successfully.",
        interviewReports
    })
}


/**
 * @description Controller to generate resume PDF based on user self description, resume and job description.
 */
async function generateResumePdfController(req, res) {
    try {
        const { interviewReportId } = req.params

        const interviewReport = await interviewReportModel.findById(interviewReportId)

        if (!interviewReport) {
            return res.status(404).json({
                message: "Interview report not found."
            })
        }

        const { resume, jobDescription, selfDescription } = interviewReport

        let pdfBuffer;
        if (interviewReport.tailoredResumeHtml) {
            console.log(`[Cache Hit] Compiling PDF from pre-stored tailored resume HTML for report ${interviewReportId}...`)
            pdfBuffer = await generatePdfFromHtml(interviewReport.tailoredResumeHtml)
        } else {
            console.log(`[Cache Miss] Fetching new resume HTML from Gemini for report ${interviewReportId}...`)
            const resumeHtml = await generateResumeHtml({ resume, jobDescription, selfDescription })
            pdfBuffer = await generatePdfFromHtml(resumeHtml)

            // Cache the generated HTML in the database to prevent duplicate Gemini API calls
            interviewReport.tailoredResumeHtml = resumeHtml
            await interviewReport.save()
            console.log(`[Cache Success] Cached resume HTML in DB for report ${interviewReportId}`)
        }

        res.set({
            "Content-Type": "application/pdf",
            "Content-Disposition": `attachment; filename=resume_${interviewReportId}.pdf`
        })

        res.send(pdfBuffer)
    } catch (error) {
        console.error("Error in generateResumePdfController:", error)
        res.status(500).json({ message: "Failed to compile resume. " + error.message })
    }
}

async function evaluateAnswerController(req, res) {
    try {
        const { question, answer, jobDescription } = req.body

        if (!question) {
            return res.status(400).json({ message: "question is required." })
        }
        if (!answer) {
            return res.status(400).json({ message: "answer is required." })
        }
        if (!jobDescription) {
            return res.status(400).json({ message: "jobDescription is required." })
        }

        const evaluation = await evaluatePracticeAnswer({ question, answer, jobDescription })

        res.status(200).json({
            message: "Answer evaluated successfully.",
            evaluation
        })
    } catch (error) {
        console.error("Error in evaluateAnswerController:", error)
        res.status(500).json({ message: "Failed to evaluate answer. " + error.message })
    }
}

module.exports = { 
    generateInterViewReportController, 
    getInterviewReportByIdController, 
    getAllInterviewReportsController, 
    generateResumePdfController,
    evaluateAnswerController
}