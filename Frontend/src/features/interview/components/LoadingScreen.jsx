import React, { useState, useEffect } from 'react'

const LoadingScreen = () => {
    const [step, setStep] = useState(0)
    const steps = [
        "Initializing AI strategy engine...",
        "Analyzing resume & profile structure...",
        "Scanning target job description requirements...",
        "Extracting core technical skill gaps...",
        "Formulating 7-day personalized prep roadmap...",
        "Synthesizing high-impact behavioral questions...",
        "Assembling tailored coding & system design challenges...",
        "Finalizing your premium strategy report..."
    ]

    useEffect(() => {
        const interval = setInterval(() => {
            setStep((prev) => (prev < steps.length - 1 ? prev + 1 : prev))
        }, 3200)
        return () => clearInterval(interval)
    }, [])

    return (
        <main className="premium-loader-container">
            <div className="cyber-loader-card">
                <div className="cyber-loader-glowing-glow" />
                <div className="cyber-loader-ring-wrapper">
                    <div className="cyber-loader-ring" />
                    <div className="cyber-loader-ring-inner" />
                    <div className="cyber-loader-core">
                        <svg className="ai-core-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 21m0 0l-.813-5.096m.813 5.096a18.665 18.665 0 01-5.185-5.185m0 0L1 15m3.815 0L1 14.187M15 11l4.813 4.904m0 0l.813-5.096M19.813 15.9a18.666 18.666 0 01-5.185 5.186m0 0l-.813-5.096m.813 5.096a18.67 18.67 0 005.185-5.185M9 3h6m-6 0a3 3 0 00-3 3v12a3 3 0 003 3h6a3 3 0 003-3V6a3 3 0 00-3-3m-6 0V1M15 3V1" />
                        </svg>
                    </div>
                </div>
                
                <h1 className="loader-title">Synthesizing Blueprint</h1>
                <p className="loader-subtitle">Please wait while the AI generates your strategy</p>

                <div className="progress-bar-container">
                    <div className="progress-bar-fill" style={{ width: `${((step + 1) / steps.length) * 100}%` }} />
                </div>

                <div className="steps-tracker">
                    <div className="active-step-indicator" />
                    <span className="current-step-text">{steps[step]}</span>
                </div>

                <div className="loader-tips">
                    <span className="tip-header">PREPARATION TIP</span>
                    <p className="tip-text">AI recommendations are specifically tuned to close the severity gaps in your profile. Focus on days 1-3 for core alignment!</p>
                </div>
            </div>
        </main>
    )
}

export default LoadingScreen
