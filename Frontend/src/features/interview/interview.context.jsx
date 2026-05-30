import React from "react";
import { createContext, useState } from "react";

export const InterviewContext = createContext()

export const InterviewProvider = ({ children }) => {
    const [loading, setLoading] = useState(false)
    const [report, setReport] = useState(null)
    const [reports, setReports] = useState([])
    const [pdfGenerating, setPdfGenerating] = useState(false)
    const [pdfStep, setPdfStep] = useState(0) // 0: Idle, 1-5: Progressive steps, 6: Success
    const [pdfError, setPdfError] = useState(null)

    return (
        <InterviewContext.Provider value={{ 
            loading, setLoading, 
            report, setReport, 
            reports, setReports,
            pdfGenerating, setPdfGenerating,
            pdfStep, setPdfStep,
            pdfError, setPdfError
        }}>
            {children}
        </InterviewContext.Provider>
    )
}