import React from "react";
import { createContext, useState } from "react";

export const InterviewContext = createContext()

export const InterviewProvider = ({ children }) => {
    const [loading, setLoading] = useState(false)
    const [report, setReport] = useState(null)
    const [reports, setReports] = useState([])
    // 'idle' | 'generating' | 'success' | 'error'. Replaces the old numeric step
    // counter, which advanced on a timer rather than on real progress.
    const [pdfStatus, setPdfStatus] = useState('idle')
    const [pdfError, setPdfError] = useState(null)

    return (
        <InterviewContext.Provider value={{
            loading, setLoading,
            report, setReport,
            reports, setReports,
            pdfStatus, setPdfStatus,
            pdfError, setPdfError
        }}>
            {children}
        </InterviewContext.Provider>
    )
}
