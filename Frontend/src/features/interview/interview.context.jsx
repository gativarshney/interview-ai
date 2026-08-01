import React from "react";
import { createContext, useState } from "react";

export const InterviewContext = createContext()

export const InterviewProvider = ({ children }) => {
    /*
      Three separate flags, because these are three different waits and each
      deserves a different treatment:
        generating    — the ~30s AI call, the only one worth a dedicated view
        reportLoading — a fast GET for one report, gets a skeleton
        listLoading   — a fast GET for the sidebar list, must not block the page

      A single shared `loading` previously drove a full-screen "Synthesizing
      Blueprint" takeover for all three, so opening the dashboard looked
      identical to running a 30-second generation.
    */
    const [generating, setGenerating] = useState(false)
    const [reportLoading, setReportLoading] = useState(false)
    const [listLoading, setListLoading] = useState(false)

    const [report, setReport] = useState(null)
    const [reports, setReports] = useState([])

    // 'idle' | 'generating' | 'success' | 'error'
    const [pdfStatus, setPdfStatus] = useState('idle')
    const [pdfError, setPdfError] = useState(null)

    return (
        <InterviewContext.Provider value={{
            generating, setGenerating,
            reportLoading, setReportLoading,
            listLoading, setListLoading,
            report, setReport,
            reports, setReports,
            pdfStatus, setPdfStatus,
            pdfError, setPdfError
        }}>
            {children}
        </InterviewContext.Provider>
    )
}
