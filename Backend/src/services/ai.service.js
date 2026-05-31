const { GoogleGenAI } = require("@google/genai")
const { z } = require("zod")
const { zodToJsonSchema } = require("zod-to-json-schema")
const puppeteer = require("puppeteer")

const ai = new GoogleGenAI({
    apiKey: process.env.GOOGLE_GENAI_API_KEY
})


const interviewReportJsonSchema = {
    type: "OBJECT",
    properties: {
        title: {
            type: "STRING",
            description: "The title of the job for which the interview report is generated"
        },
        matchScore: {
            type: "INTEGER",
            description: "A score between 0 and 100 indicating how well the candidate's profile matches the job description"
        },
        technicalQuestions: {
            type: "ARRAY",
            description: "Technical questions that can be asked in the interview along with their intention and how to answer them",
            items: {
                type: "OBJECT",
                properties: {
                    question: {
                        type: "STRING",
                        description: "The technical question can be asked in the interview"
                    },
                    intention: {
                        type: "STRING",
                        description: "The intention of interviewer behind asking this question"
                    },
                    answer: {
                        type: "STRING",
                        description: "How to answer this question, what points to cover, what approach to take etc."
                    }
                },
                required: ["question", "intention", "answer"]
            }
        },
        behavioralQuestions: {
            type: "ARRAY",
            description: "Behavioral questions that can be asked in the interview along with their intention and how to answer them",
            items: {
                type: "OBJECT",
                properties: {
                    question: {
                        type: "STRING",
                        description: "The technical question can be asked in the interview"
                    },
                    intention: {
                        type: "STRING",
                        description: "The intention of interviewer behind asking this question"
                    },
                    answer: {
                        type: "STRING",
                        description: "How to answer this question, what points to cover, what approach to take etc."
                    }
                },
                required: ["question", "intention", "answer"]
            }
        },
        skillGaps: {
            type: "ARRAY",
            description: "List of skill gaps in the candidate's profile along with their severity",
            items: {
                type: "OBJECT",
                properties: {
                    skill: {
                        type: "STRING",
                        description: "The skill which the candidate is lacking"
                    },
                    severity: {
                        type: "STRING",
                        enum: ["low", "medium", "high"],
                        description: "The severity of this skill gap, i.e. how important is this skill for the job and how much it can impact the candidate's chances"
                    }
                },
                required: ["skill", "severity"]
            }
        },
        preparationPlan: {
            type: "ARRAY",
            description: "A day-wise preparation plan for the candidate to follow in order to prepare for the interview effectively",
            items: {
                type: "OBJECT",
                properties: {
                    day: {
                        type: "INTEGER",
                        description: "The day number in the preparation plan, starting from 1"
                    },
                    focus: {
                        type: "STRING",
                        description: "The main focus of this day in the preparation plan, e.g. data structures, system design, mock interviews etc."
                    },
                    tasks: {
                        type: "ARRAY",
                        items: { type: "STRING" },
                        description: "List of tasks to be done on this day to follow the preparation plan, e.g. read a specific book or article, solve a set of problems, watch a video etc."
                    }
                },
                required: ["day", "focus", "tasks"]
            }
        }
    },
    required: ["title", "matchScore", "technicalQuestions", "behavioralQuestions", "skillGaps", "preparationPlan"]
}

function tryParseJson(value) {
    if (typeof value === "string" && value.trim().startsWith("{")) {
        try {
            return JSON.parse(value)
        } catch (e) {}
    }
    return value
}

function normalizeTechnicalQuestions(value) {
    if (!Array.isArray(value)) return []
    return value.map((item, index) => {
        const parsed = tryParseJson(item)
        if (typeof parsed === "object" && parsed !== null) {
            return {
                question: String(parsed.question || parsed.text || parsed.prompt || `Technical question ${index + 1}`),
                intention: String(parsed.intention || parsed.goal || "Assess the candidate's technical reasoning and problem-solving approach."),
                answer: String(parsed.answer || parsed.response || "Provide a concise explanation of the candidate's approach."),
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
        const parsed = tryParseJson(item)
        if (typeof parsed === "object" && parsed !== null) {
            return {
                question: String(parsed.question || parsed.text || `Behavioral question ${index + 1}`),
                intention: String(parsed.intention || parsed.goal || "Understand the candidate's teamwork and communication skills."),
                answer: String(parsed.answer || parsed.response || "Describe a relevant experience clearly and concisely."),
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
        const parsed = tryParseJson(item)
        if (typeof parsed === "object" && parsed !== null) {
            return {
                skill: String(parsed.skill || parsed.name || `Skill gap ${index + 1}`),
                severity: ["low", "medium", "high"].includes(String(parsed.severity).toLowerCase()) ? String(parsed.severity).toLowerCase() : "medium",
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
        const parsed = tryParseJson(item)
        if (typeof parsed === "object" && parsed !== null) {
            return {
                day: Number.isFinite(Number(parsed.day)) ? Number(parsed.day) : index + 1,
                focus: String(parsed.focus || parsed.goal || `Day ${index + 1} focus`),
                tasks: Array.isArray(parsed.tasks) ? parsed.tasks.map(String) : [String(parsed.task || parsed.activity || "Review and practice relevant concepts.")],
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
    try {
        const prompt = `You are generating an interview report summary. Return only valid JSON with the following fields:\n- title: the job title from the job description\n- matchScore: an integer from 0 to 100\n- technicalQuestions: an array of technical question objects ({question, intention, answer})\n- behavioralQuestions: an array of behavioral question objects ({question, intention, answer})\n- skillGaps: an array of skill gap objects ({skill, severity})\n- preparationPlan: an array of daily plan objects ({day, focus, tasks})\n\nCandidate resume: ${resume}\nCandidate self-description: ${selfDescription}\nJob description: ${jobDescription}\n\nMake sure every field is present and include real values, not empty arrays. Do not add any text outside the JSON.`

        const response = await ai.models.generateContent({
            model: "gemini-2.5-flash",
            contents: prompt,
            config: {
                responseMimeType: "application/json",
                responseSchema: interviewReportJsonSchema,
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
    } catch (error) {
        console.error("Error in generateInterviewReport AI service:", error)
        throw error
    }
}

async function generatePdfFromHtml(htmlContent) {
    const browser = await puppeteer.launch({
        args: [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage"
        ]
    })
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

const answerEvaluationJsonSchema = {
    type: "OBJECT",
    properties: {
        rating: {
            type: "STRING",
            enum: ["Excellent", "Good", "Needs Improvement"],
            description: "Quality rating of the candidate's answer."
        },
        strengths: {
            type: "ARRAY",
            description: "Bullet points detailing what the candidate did well, such as specific terms, STAR structure alignment, or logical flow.",
            items: { type: "STRING" }
        },
        improvements: {
            type: "ARRAY",
            description: "Bullet points detailing missing keywords, logical gaps, or areas of STAR structure to refine.",
            items: { type: "STRING" }
        },
        suggestedRevision: {
            type: "STRING",
            description: "A professional, refined, STAR-method aligned rewrite of the candidate's response that is suitable for a FAANG interview."
        }
    },
    required: ["rating", "strengths", "improvements", "suggestedRevision"]
}

async function evaluatePracticeAnswer({ question, answer, jobDescription }) {
    try {
        const prompt = `You are an expert FAANG technical recruiter and executive interview coach. 
Evaluate the candidate's practice answer for the following question, aligned with the target job description.

Target Job Description:
${jobDescription}

Interview Question:
${question}

Candidate's Answer:
${answer}

Assess the answer thoroughly using professional interview standards, looking for:
1. STAR method alignment (Situation, Task, Action, Result).
2. Presence of critical technical or domain keywords.
3. Logical reasoning, clarity, and conciseness.

Return a valid JSON object matching the requested schema. Provide deep, constructive, and realistic feedback. 
In the "suggestedRevision" field, rewrite their response in a highly refined, professional format that is tailored for senior FAANG recruiters.`

        const response = await ai.models.generateContent({
            model: "gemini-2.5-flash",
            contents: prompt,
            config: {
                responseMimeType: "application/json",
                responseSchema: answerEvaluationJsonSchema,
            }
        })

        const result = JSON.parse(response.text)

        return {
            rating: ["Excellent", "Good", "Needs Improvement"].includes(result.rating) ? result.rating : "Good",
            strengths: Array.isArray(result.strengths) ? result.strengths.map(String) : ["Answer provided some domain context."],
            improvements: Array.isArray(result.improvements) ? result.improvements.map(String) : ["Consider structuring your answer with more specific metrics."],
            suggestedRevision: result.suggestedRevision || "A highly refined STAR rewrite is unavailable."
        }
    } catch (error) {
        console.error("Error in evaluatePracticeAnswer AI service:", error)
        throw error
    }
}

async function generateResumeHtml({ resume, selfDescription, jobDescription }) {
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
    return jsonContent.html
}

module.exports = { generateInterviewReport, generateResumePdf, evaluatePracticeAnswer, generateResumeHtml, generatePdfFromHtml }