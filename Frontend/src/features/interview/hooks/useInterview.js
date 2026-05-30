import { getAllInterviewReports, generateInterviewReport, getInterviewReportById, generateResumePdf } from "../services/interview.api"
import { useContext, useEffect } from "react"
import { InterviewContext } from "../interview.context"
import { useParams } from "react-router-dom"
import { useToast } from "../components/Toast.jsx"


export const useInterview = () => {

    const context = useContext(InterviewContext)
    const { interviewId } = useParams()
    const { showToast } = useToast()

    if (!context) {
        throw new Error("useInterview must be used within an InterviewProvider")
    }

    const { loading, setLoading, report, setReport, reports, setReports } = context

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
        setLoading(true)
        let response = null
        try {
            response = await generateResumePdf({ interviewReportId })
            const url = window.URL.createObjectURL(new Blob([ response ], { type: "application/pdf" }))
            const link = document.createElement("a")
            link.href = url
            link.setAttribute("download", `resume_${interviewReportId}.pdf`)
            document.body.appendChild(link)
            link.click()
            showToast('ATS-optimized PDF resume generated and downloaded!', 'success')
        }
        catch (error) {
            console.error('getResumePdf error:', error)
            showToast('Failed to compile ATS-optimized PDF resume. Please try again.', 'error')
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        if (interviewId) {
            getReportById(interviewId)
        } else {
            getReports()
        }
    }, [ interviewId ])

    return { loading, report, reports, generateReport, getReportById, getReports, getResumePdf }

}