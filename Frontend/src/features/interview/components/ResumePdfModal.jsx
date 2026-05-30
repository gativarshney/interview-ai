import React from 'react'
import { useInterview } from '../hooks/useInterview'

const STEP_MESSAGES = {
    1: "Analyzing Resume Data",
    2: "Optimizing ATS Keywords",
    3: "Generating Professional Resume Layout",
    4: "Building PDF Document",
    5: "Preparing Download Assets",
    6: "Resume Ready!"
}

const ResumePdfModal = () => {
    const { pdfGenerating, pdfStep, pdfError } = useInterview()

    if (!pdfGenerating) return null

    return (
        <div className="resume-pdf-modal-overlay" aria-modal="true" role="dialog">
            <div className="resume-pdf-modal-card">
                
                {pdfError ? (
                    // Error State
                    <div className="downloader-error-state">
                        <div className="error-icon-wrapper">
                            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        </div>
                        <h3>Compilation Failed</h3>
                        <p>{pdfError}</p>
                    </div>
                ) : (
                    // Progress / Success State
                    <div className="downloader-progress-state">
                        
                        <div className="visual-loader-wrapper">
                            {pdfStep === 6 ? (
                                // Glowing success checkmark
                                <div className="success-checkmark-glow">
                                    <svg className="checkmark-svg" viewBox="0 0 52 52">
                                        <circle className="checkmark-circle" cx="26" cy="26" r="25" fill="none" />
                                        <path className="checkmark-check" fill="none" d="M14.1 27.2l7.1 7.2 16.7-16.8" />
                                    </svg>
                                </div>
                            ) : (
                                // Spinning gradient progressive ring
                                <div className="spinning-ring-wrapper">
                                    <div className="ring-spinner" />
                                    <span className="step-counter">{pdfStep}/5</span>
                                </div>
                            )}
                        </div>

                        <h3 className={pdfStep === 6 ? "success-headline text-glowing" : "loading-headline"}>
                            {pdfStep === 6 ? "ATS Optimized PDF Compiled" : "Compiling Premium Resume"}
                        </h3>
                        
                        <p className="loading-status-text">
                            {STEP_MESSAGES[pdfStep] || "Processing request..."}
                        </p>

                        {pdfStep !== 6 && (
                            <div className="stepper-indicator-dots">
                                {[1, 2, 3, 4, 5].map((s) => (
                                    <div 
                                        key={s} 
                                        className={`indicator-dot ${pdfStep === s ? 'active' : pdfStep > s ? 'completed' : ''}`}
                                    />
                                ))}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    )
}

export default ResumePdfModal
