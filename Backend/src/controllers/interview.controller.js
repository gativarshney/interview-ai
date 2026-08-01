const pdfParse = require("pdf-parse")
const { generateInterviewReport, evaluatePracticeAnswer, generateResumeHtml } = require("../services/ai.service")
const { generatePdfFromHtml } = require("../services/pdf.service")
const interviewReportModel = require("../models/interviewReport.model")
const { HttpError } = require("../middlewares/error.middleware")

const MAX_JOB_DESCRIPTION_CHARS = 8000
const MAX_SELF_DESCRIPTION_CHARS = 4000
const MAX_ANSWER_CHARS = 6000

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
    // Accept optional resume file. If present, parse PDF; otherwise use empty resume text.
    let resumeText = ""
    let resumeFilename = ""
    if (req.file && req.file.buffer) {
        try {
            const resumeContent = await (new pdfParse.PDFParse(Uint8Array.from(req.file.buffer))).getText()
            resumeText = resumeContent.text
        } catch {
            throw new HttpError(400, "We could not read that PDF. Please upload a text-based (not scanned) resume.")
        }
        resumeFilename = req.file.originalname

        if (!resumeText.trim()) {
            throw new HttpError(400, "No text could be extracted from that PDF. It may be a scanned image.")
        }
    }

    const { selfDescription, jobDescription, title } = req.body

    // Require jobDescription and at least one of selfDescription or resume
    if (!jobDescription || !String(jobDescription).trim()) {
        throw new HttpError(400, "jobDescription is required.")
    }

    if (String(jobDescription).length > MAX_JOB_DESCRIPTION_CHARS) {
        throw new HttpError(400, `Job description is too long (max ${MAX_JOB_DESCRIPTION_CHARS} characters).`)
    }

    if (selfDescription && String(selfDescription).length > MAX_SELF_DESCRIPTION_CHARS) {
        throw new HttpError(400, `Self description is too long (max ${MAX_SELF_DESCRIPTION_CHARS} characters).`)
    }

    if (!String(selfDescription || "").trim() && !resumeText) {
        throw new HttpError(400, "Either selfDescription or resume file is required.")
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
}

/**
 * @description Controller to get interview report by interviewId.
 */
async function getInterviewReportByIdController(req, res) {

    const { interviewId } = req.params

    const interviewReport = await interviewReportModel.findOne({ _id: interviewId, user: req.user.id })

    if (!interviewReport) {
        throw new HttpError(404, "Interview report not found.")
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
    const interviewReports = await interviewReportModel.find({ user: req.user.id }).sort({ createdAt: -1 }).select("-resume -selfDescription -jobDescription -__v -technicalQuestions -behavioralQuestions -preparationPlan -tailoredResumeHtml")

    res.status(200).json({
        message: "Interview reports fetched successfully.",
        interviewReports
    })
}


/**
 * @description Controller to generate resume PDF based on user self description, resume and job description.
 */
async function generateResumePdfController(req, res) {
    const { interviewReportId } = req.params

    // Scoped to the owner: a report id is guessable, and the compiled PDF
    // contains the candidate's full resume text.
    const interviewReport = await interviewReportModel.findOne({
        _id: interviewReportId,
        user: req.user.id
    })

    if (!interviewReport) {
        throw new HttpError(404, "Interview report not found.")
    }

    const { resume, jobDescription, selfDescription } = interviewReport

    let pdfBuffer;
    if (interviewReport.tailoredResumeHtml) {
        pdfBuffer = await generatePdfFromHtml(interviewReport.tailoredResumeHtml)
    } else {
        const resumeHtml = await generateResumeHtml({ resume, jobDescription, selfDescription })
        pdfBuffer = await generatePdfFromHtml(resumeHtml)

        // Cache the generated HTML so repeat downloads skip the Gemini call.
        interviewReport.tailoredResumeHtml = resumeHtml
        await interviewReport.save()
    }

    res.set({
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename=resume_${interviewReportId}.pdf`
    })

    res.send(pdfBuffer)
}

async function evaluateAnswerController(req, res) {
    const { question, answer, jobDescription } = req.body

    if (!question || !String(question).trim()) {
        throw new HttpError(400, "question is required.")
    }
    if (!answer || !String(answer).trim()) {
        throw new HttpError(400, "answer is required.")
    }
    if (!jobDescription || !String(jobDescription).trim()) {
        throw new HttpError(400, "jobDescription is required.")
    }
    if (String(answer).length > MAX_ANSWER_CHARS) {
        throw new HttpError(400, `Answer is too long (max ${MAX_ANSWER_CHARS} characters).`)
    }

    const evaluation = await evaluatePracticeAnswer({ question, answer, jobDescription })

    res.status(200).json({
        message: "Answer evaluated successfully.",
        evaluation
    })
}

module.exports = {
    generateInterViewReportController,
    getInterviewReportByIdController,
    getAllInterviewReportsController,
    generateResumePdfController,
    evaluateAnswerController
}
