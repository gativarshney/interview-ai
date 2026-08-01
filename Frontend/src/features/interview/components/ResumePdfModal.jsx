import React from 'react'
import { useInterview } from '../hooks/useInterview'

/**
 * The server does not stream progress for resume generation, so this shows the
 * three states we can actually observe: working, done, failed. It previously
 * animated through five invented "steps" on a timer.
 */
const ResumePdfModal = () => {
    const { pdfStatus, pdfError } = useInterview()

    if (pdfStatus === 'idle') return null

    return (
        <div className="resume-pdf-modal-overlay" aria-modal="true" role="dialog" aria-live="polite">
            <div className="resume-pdf-modal-card">

                {pdfStatus === 'error' ? (
                    <div className="downloader-error-state">
                        <div className="error-icon-wrapper">
                            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        </div>
                        <h3>Resume Generation Failed</h3>
                        <p>{pdfError}</p>
                    </div>
                ) : (
                    <div className="downloader-progress-state">

                        <div className="visual-loader-wrapper">
                            {pdfStatus === 'success' ? (
                                <div className="success-checkmark-glow">
                                    <svg className="checkmark-svg" viewBox="0 0 52 52">
                                        <circle className="checkmark-circle" cx="26" cy="26" r="25" fill="none" />
                                        <path className="checkmark-check" fill="none" d="M14.1 27.2l7.1 7.2 16.7-16.8" />
                                    </svg>
                                </div>
                            ) : (
                                <div className="spinning-ring-wrapper">
                                    <div className="ring-spinner" />
                                </div>
                            )}
                        </div>

                        <h3 className={pdfStatus === 'success' ? "success-headline text-glowing" : "loading-headline"}>
                            {pdfStatus === 'success' ? "Resume Ready" : "Generating Your Resume"}
                        </h3>

                        <p className="loading-status-text">
                            {pdfStatus === 'success'
                                ? "Your download should begin automatically."
                                : "Tailoring your resume to the job description. This usually takes 10–20 seconds."}
                        </p>
                    </div>
                )}
            </div>
        </div>
    )
}

export default ResumePdfModal
