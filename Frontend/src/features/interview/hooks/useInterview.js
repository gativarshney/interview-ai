import { getAllInterviewReports, generateInterviewReport, getInterviewReportById, generateResumePdf, evaluatePracticeAnswer } from "../services/interview.api"
import { useContext, useEffect } from "react"
import { InterviewContext } from "../interview.context"
import { useParams } from "react-router-dom"
import { useToast } from "../components/Toast.jsx"

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
    if (msg.includes('resume') || msg.includes('pdf') || msg.includes('html'))
        return 'Failed to generate the resume PDF. Please try again.'
    return 'Something went wrong on our end. Please try again in a moment.'
}


export const useInterview = () => {

    const context = useContext(InterviewContext)
    const { interviewId } = useParams()
    const { showToast } = useToast()

    if (!context) {
        throw new Error("useInterview must be used within an InterviewProvider")
    }

    const { 
        loading, setLoading, 
        report, setReport, 
        reports, setReports,
        pdfGenerating, setPdfGenerating,
        pdfStep, setPdfStep,
        pdfError, setPdfError
    } = context

    const generateReport = async ({ jobDescription, selfDescription, resumeFile }) => {
        setLoading(true)
        let response = null
        try {
            response = await generateInterviewReport({ jobDescription, selfDescription, resumeFile })
            if (response && response.interviewReport) {
                setReport(response.interviewReport)
            } else {
                console.error('generateInterviewReport returned no interviewReport', response)
                showToast('Failed to parse the generated interview strategy. Please try again.', 'error')
            }
        } catch (error) {
            console.error('generateReport error:', error)
            const msg = error.response?.data?.message || 'Failed to connect to AI generation server. Please try again.'
            showToast(msg, 'error')
        } finally {
            setLoading(false)
        }

        return response?.interviewReport ?? null
    }

    const getReportById = async (interviewId) => {
        setLoading(true)
        let response = null
        try {
            response = await getInterviewReportById(interviewId)
            if (response && response.interviewReport) {
                setReport(response.interviewReport)
            } else {
                console.error('getInterviewReportById returned no interviewReport', response)
                setReport(null)
                showToast('Could not find the requested interview plan.', 'warning')
            }
        } catch (error) {
            console.error('getReportById error:', error)
            showToast('Failed to retrieve the interview plan. Please check your connection.', 'error')
        } finally {
            setLoading(false)
        }
        return response?.interviewReport ?? null
    }

    const getReports = async () => {
        setLoading(true)
        let response = null
        try {
            response = await getAllInterviewReports()
            if (response && response.interviewReports) {
                setReports(response.interviewReports)
            } else {
                console.error('getAllInterviewReports returned no interviewReports', response)
                setReports([])
            }
        } catch (error) {
            console.error('getReports error:', error)
            showToast('Failed to load recent plans.', 'error')
        } finally {
            setLoading(false)
        }

        return response?.interviewReports ?? []
    }

    const getResumePdf = async (interviewReportId) => {
        setPdfGenerating(true)
        setPdfError(null)
        setPdfStep(1) // Step 1: Analyzing Resume Data

        // Progressive steps timer (faked interval for ultra-premium feel)
        let currentStep = 1
        const timer = setInterval(() => {
            if (currentStep < 3) {
                currentStep += 1
                setPdfStep(currentStep) // Step 2: Optimizing ATS Keywords -> Step 3: Generating Layout
            }
        }, 2200)

        try {
            const response = await generateResumePdf({ interviewReportId })
            
            clearInterval(timer)
            setPdfStep(4) // Step 4: Building PDF
            
            await new Promise(r => setTimeout(r, 1000))
            setPdfStep(5) // Step 5: Preparing Download

            await new Promise(r => setTimeout(r, 1000))
            setPdfStep(6) // Step 6: Success! Resume Ready

            const url = window.URL.createObjectURL(new Blob([ response ], { type: "application/pdf" }))
            const link = document.createElement("a")
            link.href = url
            link.setAttribute("download", `resume_${interviewReportId}.pdf`)
            document.body.appendChild(link)
            link.click()
            document.body.removeChild(link)
            
            showToast('ATS-optimized PDF resume compiled successfully!', 'success')
            
            // Wait in success state for visual completion
            await new Promise(r => setTimeout(r, 1600))
        }
        catch (error) {
            clearInterval(timer)
            console.error('getResumePdf error:', error)
            let friendlyMessage = 'Something went wrong while generating your resume. Please try again.'
            try {
                if (error.response?.data instanceof Blob) {
                    const text = await error.response.data.text()
                    const json = JSON.parse(text)
                    if (json.message) friendlyMessage = toFriendlyError(json.message)
                } else if (error.response?.data?.message) {
                    friendlyMessage = toFriendlyError(error.response.data.message)
                } else if (!error.response) {
                    friendlyMessage = 'Unable to reach the server. Please check your connection and try again.'
                }
            } catch {}
            setPdfError(friendlyMessage)
            showToast(friendlyMessage, 'error')
            await new Promise(r => setTimeout(r, 3000))
        } finally {
            setPdfGenerating(false)
            setPdfStep(0)
            setPdfError(null)
        }
    }

    const evaluateAnswer = async ({ question, answer, jobDescription }) => {
        try {
            const response = await evaluatePracticeAnswer({ question, answer, jobDescription })
            return response.evaluation ?? null
        } catch (error) {
            console.error('evaluateAnswer error:', error)
            const msg = error.response?.data?.message || 'Failed to submit practice answer. Please try again.'
            showToast(msg, 'error')
            return null
        }
    }

    useEffect(() => {
        if (interviewId) {
            if (!report || report._id !== interviewId) {
                getReportById(interviewId)
            }
        } else {
            getReports()
        }
    }, [ interviewId, report ])

    return { 
        loading, report, reports, 
        pdfGenerating, pdfStep, pdfError, 
        generateReport, getReportById, getReports, getResumePdf, evaluateAnswer 
    }

}