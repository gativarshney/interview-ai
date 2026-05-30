import React, { useState, useRef } from 'react'
import '../styles/home.scss'
import { useInterview } from '../hooks/useInterview.js'
import { useNavigate } from 'react-router-dom'
import LoadingScreen from '../components/LoadingScreen.jsx'
import { useToast } from '../components/Toast.jsx'
import useAuth from '../../auth/hooks/useAuth.js'

const Home = () => {
    const { loading, generateReport, reports } = useInterview()
    const { user } = useAuth()
    const { showToast } = useToast()
    const navigate = useNavigate()

    const [ jobDescription, setJobDescription ] = useState("")
    const [ selfDescription, setSelfDescription ] = useState("")
    const [ selectedFile, setSelectedFile ] = useState(null)
    const [ fileUpdatedTime, setFileUpdatedTime ] = useState("")
    const [ validationErrors, setValidationErrors ] = useState({ jobDescription: false, profile: false })
    
    const resumeInputRef = useRef()

    const handleFileChange = (e) => {
        if (e.target.files && e.target.files[0]) {
            const file = e.target.files[0]
            setSelectedFile(file)
            setFileUpdatedTime(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))
            setValidationErrors((prev) => ({ ...prev, profile: false }))
            showToast(`Resume "${file.name}" uploaded successfully.`, 'success')
        }
    }

    const handleRemoveFile = () => {
        setSelectedFile(null)
        setFileUpdatedTime("")
        if (resumeInputRef.current) {
            resumeInputRef.current.value = ""
        }
        showToast('Resume removed.', 'info')
    }

    const handleGenerateReport = async () => {
        const resumeFile = selectedFile

        let hasError = false
        const errors = { jobDescription: false, profile: false }

        if (!jobDescription || jobDescription.trim() === "") {
            errors.jobDescription = true
            hasError = true
        }

        if (!resumeFile && (!selfDescription || selfDescription.trim() === "")) {
            errors.profile = true
            hasError = true
        }

        if (hasError) {
            setValidationErrors(errors)
            showToast('Please provide a target job description and either a resume or self-description.', 'warning')
            return
        }

        // Clear validation errors
        setValidationErrors({ jobDescription: false, profile: false })

        try {
            const data = await generateReport({ jobDescription, selfDescription, resumeFile })
            if (data && data._id) {
                showToast('Interview strategy blueprint synthesized successfully!', 'success')
                navigate(`/interview/${data._id}`)
            } else {
                console.error('Report generation did not return an id', data)
                showToast('Could not generate interview report. Please try again.', 'error')
            }
        } catch (err) {
            console.error('Error generating report:', err)
            showToast('An error occurred while generating the report.', 'error')
        }
    }

    if (loading) {
        return <LoadingScreen />
    }

    return (
        <div className="dashboard-layout-container">
            {/* Glassmorphic Left Sidebar */}
            <aside className="dashboard-sidebar">
                <div className="sidebar-brand">
                    <div className="brand-dot" />
                    <span>Interview Copilot</span>
                </div>

                <button className="sidebar-action-btn active" onClick={() => navigate('/generate')}>
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                    New Strategy
                </button>

                <nav className="sidebar-nav">
                    <button className="sidebar-nav-link" onClick={() => navigate('/dashboard')}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                        Dashboard
                    </button>
                    <button className="sidebar-nav-link active" onClick={() => navigate('/generate')}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                        7-Day Roadmap
                    </button>
                    <button className="sidebar-nav-link" onClick={handleDownloadResume}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                        ATS Resume Downloader
                    </button>
                    <button className="sidebar-nav-link" onClick={triggerMockAlert}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                        Mock Practice
                    </button>
                </nav>

                <div className="sidebar-recents">
                    <span className="recents-header">Recent Strategies</span>
                    <div className="recents-list">
                        {reports && reports.length > 0 ? (
                            reports.slice(0, 4).map(r => (
                                <button key={r._id} className="recent-item-link" onClick={() => navigate(`/interview/${r._id}`)}>
                                    <span className="recent-dot" />
                                    <span className="recent-title">{r.title || 'Untitled Strategy'}</span>
                                </button>
                            ))
                        ) : (
                            <span className="no-recents-text">No plans created yet</span>
                        )}
                    </div>
                </div>

                <div className="sidebar-user-profile">
                    <div className="user-avatar">
                        {user?.username ? user.username.charAt(0).toUpperCase() : 'C'}
                    </div>
                    <div className="user-meta">
                        <span className="user-name">{user?.username || 'Candidate'}</span>
                        <span className="user-email">{user?.email || 'candidate@gmail.com'}</span>
                    </div>
                    <button className="logout-icon-btn" onClick={handleLogout} title="Logout">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                    </button>
                </div>
            </aside>

            {/* Main Generation Panel Content Area */}
            <main className="dashboard-main-content">
                <header className="workspace-header">
                    <div className="header-breadcrumbs">
                        <span>Coach</span>
                        <span className="breadcrumb-separator">/</span>
                        <span className="breadcrumb-active">Create plan</span>
                    </div>
                    <button className="back-dash-btn" onClick={() => navigate('/dashboard')} style={{ margin: 0 }}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
                        Back to Dashboard
                    </button>
                </header>

                {/* Copilot Generation Welcome */}
                <section className="copilot-prompt-hero" style={{ padding: '2rem 1.5rem 1.5rem 1.5rem' }}>
                    <div className="copilot-tag" style={{ border: '1px solid rgba(255, 45, 120, 0.25)', backgroundColor: 'rgba(255, 45, 120, 0.05)', color: '#ff2d78' }}>
                        AI Synthesis Studio
                    </div>
                    
                    <h1 className="copilot-title" style={{ fontSize: '2.35rem', maxWidth: '720px' }}>
                        Create Your Custom <span className="highlight-text-gradient">Interview Plan</span>
                    </h1>
                    
                    <p className="copilot-subtitle" style={{ maxWidth: '600px', margin: 0 }}>
                        Tell our AI your target job details and upload your profile background. We will instantly synthesize a personalized, 7-day preparation roadmap and audit your ATS match score.
                    </p>
                </section>

                {/* Interactive Form Card */}
                <div className="interview-card">
                    <div className="interview-card__body">

                        {/* Left Panel - Job Description */}
                        <div className="panel panel--left">
                            <div className="panel__header">
                                <span className="panel__icon">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2" /><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" /></svg>
                                </span>
                                <h2>Target Job Description</h2>
                                <span className="badge badge--required">Required</span>
                            </div>
                            <textarea
                                value={jobDescription}
                                onChange={(e) => {
                                    setJobDescription(e.target.value)
                                    if (e.target.value.trim() !== "") {
                                        setValidationErrors((prev) => ({ ...prev, jobDescription: false }))
                                    }
                                }}
                                className={`panel__textarea ${validationErrors.jobDescription ? 'panel__textarea--error' : ''}`}
                                placeholder={`Paste the full job description here...\ne.g. 'Senior Frontend Engineer at Google requires proficiency in React, TypeScript, and large-scale system design...'`}
                                maxLength={5000}
                            />
                            <div className="char-counter">{jobDescription.length} / 5000 chars</div>
                        </div>

                        {/* Vertical Divider */}
                        <div className="panel-divider" />

                        {/* Right Panel - Profile Upload & Description */}
                        <div className="panel panel--right">
                            <div className="panel__header">
                                <span className="panel__icon">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                                </span>
                                <h2>Your Profile</h2>
                            </div>

                            {/* Upload Resume */}
                            <div className="upload-section">
                                <label className="section-label">
                                    Upload Resume
                                    <span className="badge badge--best">Best Results</span>
                                </label>

                                {selectedFile ? (
                                    <div className="uploaded-file-card">
                                        <div className="uploaded-file-card__icon">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                                        </div>
                                        <div className="uploaded-file-card__details">
                                            <p className="uploaded-file-card__name">{selectedFile.name}</p>
                                            <p className="uploaded-file-card__meta">
                                                {(selectedFile.size / 1024 / 1024).toFixed(2)} MB &bull; Uploaded
                                            </p>
                                            <p className="uploaded-file-card__date">
                                                Added: {fileUpdatedTime}
                                            </p>
                                        </div>
                                        <div className="uploaded-file-card__status">
                                            <span className="status-badge">
                                                <span className="status-badge__dot"></span>
                                                Ready
                                            </span>
                                            <button
                                                type="button"
                                                className="remove-file-btn"
                                                onClick={handleRemoveFile}
                                                title="Remove resume"
                                            >
                                                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                                            </button>
                                        </div>
                                    </div>
                                ) : (
                                    <label className={`dropzone ${validationErrors.profile ? 'dropzone--error' : ''}`} htmlFor="resume">
                                        <span className="dropzone__icon">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 16 12 12 8 16" /><line x1="12" y1="12" x2="12" y2="21" /><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3" /></svg>
                                        </span>
                                        <p className="dropzone__title">Click to upload or drag &amp; drop</p>
                                        <p className="dropzone__subtitle">PDF or DOCX (Max 5MB)</p>
                                        <input
                                            ref={resumeInputRef}
                                            hidden
                                            type="file"
                                            id="resume"
                                            name="resume"
                                            accept=".pdf,.docx"
                                            onChange={handleFileChange}
                                        />
                                    </label>
                                )}
                            </div>

                            {/* OR Divider */}
                            <div className="or-divider"><span>OR</span></div>

                            {/* Quick Self-Description */}
                            <div className="self-description">
                                <label className="section-label" htmlFor="selfDescription">Quick Self-Description</label>
                                <textarea
                                    value={selfDescription}
                                    onChange={(e) => {
                                        setSelfDescription(e.target.value)
                                        if (e.target.value.trim() !== "") {
                                            setValidationErrors((prev) => ({ ...prev, profile: false }))
                                        }
                                    }}
                                    id="selfDescription"
                                    name="selfDescription"
                                    className={`panel__textarea panel__textarea--short ${validationErrors.profile ? 'panel__textarea--error' : ''}`}
                                    placeholder="Briefly describe your experience, key skills, and target roles if you don't have a resume handy..."
                                />
                            </div>

                            {/* Info Box */}
                            <div className="info-box">
                                <span className="info-box__icon">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" stroke="#080710" strokeWidth="2.5" /><line x1="12" y1="16" x2="12.01" y2="16" stroke="#080710" strokeWidth="2.5" /></svg>
                                </span>
                                <p>Either a <strong>Resume</strong> or a <strong>Self Description</strong> is required to generate a personalized blueprint.</p>
                            </div>
                        </div>
                    </div>

                    {/* Card Footer */}
                    <div className="interview-card__footer">
                        <span className="footer-info">AI-Powered Strategy Generation &bull; Approx 30s</span>
                        <button
                            onClick={handleGenerateReport}
                            className="generate-btn">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z" /></svg>
                            Generate My Interview Strategy
                        </button>
                    </div>
                </div>
            </main>
        </div>
    )
}

export default Home