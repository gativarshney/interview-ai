const { GoogleGenAI } = require("@google/genai")
const { z } = require("zod")
const { zodToJsonSchema } = require("zod-to-json-schema")
const puppeteer = require("puppeteer")

const ai = new GoogleGenAI({
    apiKey: process.env.GOOGLE_GENAI_API_KEY
})


const interviewReportSchema = z.object({
    matchScore: z.number().describe("A score between 0 and 100 indicating how well the candidate's profile matches the job describe"),

    technicalQuestions: z.array(z.object({
        question: z.string().describe("The technical question can be asked in the interview"),
        intention: z.string().describe("The intention of interviewer behind asking this question"),
        answer: z.string().describe("How to answer this question, what points to cover, what approach to take etc.")
    })).describe("Technical questions that can be asked in the interview along with their intention and how to answer them"),

    behavioralQuestions: z.array(z.object({
        question: z.string().describe("The technical question can be asked in the interview"),
        intention: z.string().describe("The intention of interviewer behind asking this question"),
        answer: z.string().describe("How to answer this question, what points to cover, what approach to take etc.")
    })).describe("Behavioral questions that can be asked in the interview along with their intention and how to answer them"),

    skillGaps: z.array(z.object({
        skill: z.string().describe("The skill which the candidate is lacking"),
        severity: z.enum([ "low", "medium", "high" ]).describe("The severity of this skill gap, i.e. how important is this skill for the job and how much it can impact the candidate's chances")
    })).describe("List of skill gaps in the candidate's profile along with their severity"),

    preparationPlan: z.array(z.object({
        day: z.number().describe("The day number in the preparation plan, starting from 1"),
        focus: z.string().describe("The main focus of this day in the preparation plan, e.g. data structures, system design, mock interviews etc."),
        tasks: z.array(z.string()).describe("List of tasks to be done on this day to follow the preparation plan, e.g. read a specific book or article, solve a set of problems, watch a video etc.")
    })).describe("A day-wise preparation plan for the candidate to follow in order to prepare for the interview effectively"),

    title: z.string().describe("The title of the job for which the interview report is generated"),
})

function normalizeTechnicalQuestions(value) {
    if (!Array.isArray(value)) return []
    return value.map((item, index) => {
        if (typeof item === "object" && item !== null) {
            return {
                question: String(item.question || item.text || item.prompt || `Technical question ${index + 1}`),
                intention: String(item.intention || item.goal || "Assess the candidate's technical reasoning and problem-solving approach."),
                answer: String(item.answer || item.response || "Provide a concise explanation of the candidate's approach."),
            }
        }
        const text = String(item || `Technical question ${index + 1}`)
        return {
            question: text,
            intention: "Assess the candidate's technical reasoning and problem-solving approach.",
            answer: "Provide a concise explanation of the candidate's approach.",
        }
    })
}

function normalizeBehavioralQuestions(value) {
    if (!Array.isArray(value)) return []
    return value.map((item, index) => {
        if (typeof item === "object" && item !== null) {
            return {
                question: String(item.question || item.text || `Behavioral question ${index + 1}`),
                intention: String(item.intention || item.goal || "Understand the candidate's teamwork and communication skills."),
                answer: String(item.answer || item.response || "Describe a relevant experience clearly and concisely."),
            }
        }
        const text = String(item || `Behavioral question ${index + 1}`)
        return {
            question: text,
            intention: "Understand the candidate's teamwork and communication skills.",
            answer: "Describe a relevant experience clearly and concisely.",
        }
    })
}

function normalizeSkillGaps(value) {
    if (!Array.isArray(value)) return []
    return value.map((item, index) => {
        if (typeof item === "object" && item !== null) {
            return {
                skill: String(item.skill || item.name || `Skill gap ${index + 1}`),
                severity: ["low", "medium", "high"].includes(String(item.severity).toLowerCase()) ? String(item.severity).toLowerCase() : "medium",
            }
        }
        return {
            skill: String(item || `Skill gap ${index + 1}`),
            severity: "medium",
        }
    })
}

function normalizePreparationPlan(value) {
    if (!Array.isArray(value)) return []
    return value.map((item, index) => {
        if (typeof item === "object" && item !== null) {
            return {
                day: Number.isFinite(Number(item.day)) ? Number(item.day) : index + 1,
                focus: String(item.focus || item.goal || `Day ${index + 1} focus`),
                tasks: Array.isArray(item.tasks) ? item.tasks.map(String) : [String(item.task || item.activity || "Review and practice relevant concepts.")],
            }
        }
        return {
            day: index + 1,
            focus: String(item || `Day ${index + 1} focus`),
            tasks: ["Review and practice relevant concepts."],
        }
    })
}

async function generateInterviewReport({ resume, selfDescription, jobDescription }) {

    const prompt = `You are generating an interview report summary. Return only valid JSON with the following fields:\n- title: the job title from the job description\n- matchScore: an integer from 0 to 100\n- technicalQuestions: an array of technical question objects ({question, intention, answer})\n- behavioralQuestions: an array of behavioral question objects ({question, intention, answer})\n- skillGaps: an array of skill gap objects ({skill, severity})\n- preparationPlan: an array of daily plan objects ({day, focus, tasks})\n\nCandidate resume: ${resume}\nCandidate self-description: ${selfDescription}\nJob description: ${jobDescription}\n\nMake sure every field is present and include real values, not empty arrays. Do not add any text outside the JSON.`

    const response = await ai.models.generateContent({
        model: "gemini-2.5-flash",
        contents: prompt,
        config: {
            responseMimeType: "application/json",
            responseSchema: zodToJsonSchema(interviewReportSchema),
        }
    })

    const result = JSON.parse(response.text)

    return {
        title: result.title || jobDescription.split("\n")[0]?.replace(/^Position\s*[:\-]\s*/i, "")?.trim() || "Untitled Job",
        matchScore: Number.isFinite(result.matchScore) ? result.matchScore : 0,
        technicalQuestions: normalizeTechnicalQuestions(result.technicalQuestions),
        behavioralQuestions: normalizeBehavioralQuestions(result.behavioralQuestions),
        skillGaps: normalizeSkillGaps(result.skillGaps),
        preparationPlan: normalizePreparationPlan(result.preparationPlan),
    }
}

async function generatePdfFromHtml(htmlContent) {
    const browser = await puppeteer.launch()
    const page = await browser.newPage();
    await page.setContent(htmlContent, { waitUntil: "networkidle0" })

    const pdfBuffer = await page.pdf({
        format: "A4", margin: {
            top: "20mm",
            bottom: "20mm",
            left: "15mm",
            right: "15mm"
        }
    })

    await browser.close()

    return pdfBuffer
}

async function generateResumePdf({ resume, selfDescription, jobDescription }) {

    const resumePdfSchema = z.object({
        html: z.string().describe("The HTML content of the resume which can be converted to PDF using any library like puppeteer")
    })

    const prompt = `Generate resume for a candidate with the following details:
                        Resume: ${resume}
                        Self Description: ${selfDescription}
                        Job Description: ${jobDescription}

                        the response should be a JSON object with a single field "html" which contains the HTML content of the resume which can be converted to PDF using any library like puppeteer.
                        The resume should be tailored for the given job description and should highlight the candidate's strengths and relevant experience. The HTML content should be well-formatted and structured, making it easy to read and visually appealing.
                        The content of resume should be not sound like it's generated by AI and should be as close as possible to a real human-written resume.
                        you can highlight the content using some colors or different font styles but the overall design should be simple and professional.
                        The content should be ATS friendly, i.e. it should be easily parsable by ATS systems without losing important information.
                        The resume should not be so lengthy, it should ideally be 1-2 pages long when converted to PDF. Focus on quality rather than quantity and make sure to include all the relevant information that can increase the candidate's chances of getting an interview call for the given job description.
                    `

    const response = await ai.models.generateContent({
        model: "gemini-2.5-flash",
        contents: prompt,
        config: {
            responseMimeType: "application/json",
            responseSchema: zodToJsonSchema(resumePdfSchema),
        }
    })


    const jsonContent = JSON.parse(response.text)

    const pdfBuffer = await generatePdfFromHtml(jsonContent.html)

    return pdfBuffer

}

module.exports = { generateInterviewReport, generateResumePdf }