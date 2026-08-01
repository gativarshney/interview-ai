import axios from "axios";

const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || "http://localhost:5000",
    withCredentials: true,
})


/**
 * @description Service to generate interview report based on user self description, resume and job description.
 */
export const generateInterviewReport = async ({ jobDescription, selfDescription, resumeFile }) => {

    const formData = new FormData()
    formData.append("jobDescription", jobDescription)

    if (selfDescription) {
        formData.append("selfDescription", selfDescription)
    }

    // Only append when a file was actually chosen — appending a null value
    // sends the literal string "null" as the field.
    if (resumeFile) {
        formData.append("resume", resumeFile)
    }

    // Let the browser set Content-Type so the multipart boundary is included.
    const response = await api.post("/api/interview/", formData)

    return response.data

}


/**
 * @description Service to get interview report by interviewId.
 */
export const getInterviewReportById = async (interviewId) => {
    const response = await api.get(`/api/interview/report/${interviewId}`)

    return response.data
}


/**
 * @description Service to get all interview reports of logged in user.
 */
export const getAllInterviewReports = async () => {
    const response = await api.get("/api/interview/")

    return response.data
}


/**
 * @description Service to generate resume pdf based on user self description, resume content and job description.
 */
export const generateResumePdf = async ({ interviewReportId }) => {
    const response = await api.post(`/api/interview/resume/pdf/${interviewReportId}`, null, {
        responseType: "blob"
    })

    return response.data
}

/**
 * @description Service to evaluate candidate's practice answer against job description and mock questions.
 */
export const evaluatePracticeAnswer = async ({ question, answer, jobDescription }) => {
    const response = await api.post("/api/interview/practice/evaluate", { question, answer, jobDescription })
    return response.data
}
