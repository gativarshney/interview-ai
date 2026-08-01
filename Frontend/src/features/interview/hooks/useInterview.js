import { getAllInterviewReports, generateInterviewReport, getInterviewReportById, generateResumePdf, evaluatePracticeAnswer } from "../services/interview.api"
import { useCallback, useContext } from "react"
import { InterviewContext } from "../interview.context"
import { useToast } from "../components/Toast.jsx"

// How long the "done" state stays on screen before the modal closes. This is
// UI acknowledgement of a finished action, not simulated work.
const SUCCESS_DISPLAY_MS = 1200

const toFriendlyError = (raw = '') => {
    const msg = raw.toLowerCase()
    if (msg.includes('browser') || msg.includes('chrome') || msg.includes('puppeteer') || msg.includes('executable'))
        return 'Our PDF generator is currently unavailable. Please try again in a moment.'
    if (msg.includes('timeout') || msg.includes('timed out'))
        return 'The request timed out. Please try again.'
    if (msg.includes('not found') || msg.includes('404'))
        return 'Interview report not found. Please go back and try again.'
    if (msg.includes('unauthorized') || msg.includes('401') || msg.includes('403'))
        return 'Your session has expired. Please log in again.'
    if (msg.includes('limit'))
        return 'You have hit the generation limit for now. Please try again later.'
    if (msg.includes('resume') || msg.includes('pdf') || msg.includes('html'))
        return 'Failed to generate the resume PDF. Please try again.'
    return 'Something went wrong on our end. Please try again in a moment.'
}


export const useInterview = () => {

    const context = useContext(InterviewContext)
    const { showToast } = useToast()

    if (!context) {
        throw new Error("useInterview must be used within an InterviewProvider")
    }

    const {
        generating, setGenerating,
        reportLoading, setReportLoading,
        listLoading, setListLoading,
        report, setReport,
        reports, setReports,
        pdfStatus, setPdfStatus,
        pdfError, setPdfError
    } = context

    const generateReport = useCallback(async ({ jobDescription, selfDescription, resumeFile }) => {
        setGenerating(true)
        try {
            const response = await generateInterviewReport({ jobDescription, selfDescription, resumeFile })
            if (response?.interviewReport) {
                setReport(response.interviewReport)
                return response.interviewReport
            }
            showToast('Failed to parse the generated interview strategy. Please try again.', 'error')
            return null
        } catch (error) {
            const msg = error.response?.data?.message || 'Failed to reach the AI generation server. Please try again.'
            showToast(msg, 'error')
            return null
        } finally {
            setGenerating(false)
        }
    }, [setGenerating, setReport, showToast])

    const getReportById = useCallback(async (interviewId) => {
        setReportLoading(true)
        try {
            const response = await getInterviewReportById(interviewId)
            if (response?.interviewReport) {
                setReport(response.interviewReport)
                return response.interviewReport
            }
            setReport(null)
            showToast('Could not find the requested interview plan.', 'warning')
            return null
        } catch (error) {
            setReport(null)
            const msg = error.response?.data?.message || 'Failed to retrieve the interview plan.'
            showToast(msg, 'error')
            return null
        } finally {
            setReportLoading(false)
        }
    }, [setReportLoading, setReport, showToast])

    const getReports = useCallback(async () => {
        setListLoading(true)
        try {
            const response = await getAllInterviewReports()
            const list = response?.interviewReports ?? []
            setReports(list)
            return list
        } catch {
            showToast('Failed to load recent plans.', 'error')
            return []
        } finally {
            setListLoading(false)
        }
    }, [setListLoading, setReports, showToast])

    const getResumePdf = useCallback(async (interviewReportId) => {
        setPdfError(null)
        setPdfStatus('generating')

        try {
            const blob = await generateResumePdf({ interviewReportId })

            const url = window.URL.createObjectURL(new Blob([blob], { type: "application/pdf" }))
            const link = document.createElement("a")
            link.href = url
            link.setAttribute("download", `resume_${interviewReportId}.pdf`)
            document.body.appendChild(link)
            link.click()
            document.body.removeChild(link)
            // Release the object URL; without this the blob stays in memory for
            // the life of the tab.
            window.URL.revokeObjectURL(url)

            setPdfStatus('success')
            showToast('Your tailored resume PDF is ready.', 'success')
            await new Promise(r => setTimeout(r, SUCCESS_DISPLAY_MS))
        }
        catch (error) {
            let friendlyMessage = 'Something went wrong while generating your resume. Please try again.'
            try {
                if (error.response?.data instanceof Blob) {
                    // The endpoint responds with a PDF stream, so an error body
                    // arrives as a Blob and has to be read back as text.
                    const text = await error.response.data.text()
                    const json = JSON.parse(text)
                    if (json.message) friendlyMessage = toFriendlyError(json.message)
                } else if (error.response?.data?.message) {
                    friendlyMessage = toFriendlyError(error.response.data.message)
                } else if (!error.response) {
                    friendlyMessage = 'Unable to reach the server. Please check your connection and try again.'
                }
            } catch { /* keep the generic message */ }

            setPdfStatus('error')
            setPdfError(friendlyMessage)
            showToast(friendlyMessage, 'error')
            await new Promise(r => setTimeout(r, 2500))
        } finally {
            setPdfStatus('idle')
            setPdfError(null)
        }
    }, [setPdfError, setPdfStatus, showToast])

    const evaluateAnswer = useCallback(async ({ question, answer, jobDescription }) => {
        try {
            const response = await evaluatePracticeAnswer({ question, answer, jobDescription })
            return response.evaluation ?? null
        } catch (error) {
            const msg = error.response?.data?.message || 'Failed to submit practice answer. Please try again.'
            showToast(msg, 'error')
            return null
        }
    }, [showToast])

    return {
        generating, reportLoading, listLoading,
        report, reports,
        pdfStatus, pdfError, pdfGenerating: pdfStatus !== 'idle',
        generateReport, getReportById, getReports, getResumePdf, evaluateAnswer
    }
}
