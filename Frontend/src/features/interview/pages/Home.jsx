import React, { useState, useRef } from 'react'
import '../styles/home.scss'
import { useInterview } from '../hooks/useInterview.js'
import { useNavigate } from 'react-router-dom'
import LoadingScreen from '../components/LoadingScreen.jsx'
import { useToast } from '../components/Toast.jsx'
import useAuth from '../../auth/hooks/useAuth.js'

const Home = () => {
    const { loading, generateReport, reports } = useInterview()
    const { user, handleLogout } = useAuth()
    const { showToast } = useToast()
    const navigate = useNavigate()

    const [ jobDescription, setJobDescription ] = useState("")
    const [ selfDescription, setSelfDescription ] = useState("")
    const [ selectedFile, setSelectedFile ] = useState(null)
    const [ fileUpdatedTime, setFileUpdatedTime ] = useState("")
    const [ validationErrors, setValidationErrors ] = useState({ jobDescription: false, profile: false })
    const [ dragActive, setDragActive ] = useState(false)
    const [ mobileMenuOpen, setMobileMenuOpen ] = useState(false)
    
    const resumeInputRef = useRef()

    // Smooth Scroll Helper
    const handleScrollTo = (e, id) => {
        e.preventDefault()
        const element = document.getElementById(id)
        if (element) {
            element.scrollIntoView({ behavior: 'smooth', block: 'start' })
        }
    }

    // Active Synthesis Trigger from Floating Navbar
    const handleNavbarGenerateReport = (e) => {
        e.preventDefault()
        const hasJobDesc = jobDescription && jobDescription.trim() !== ""
        const hasProfile = selectedFile || (selfDescription && selfDescription.trim() !== "")

        if (hasJobDesc && hasProfile) {
            handleGenerateReport()
        } else {
            const element = document.getElementById('workspace')
            if (element) {
                element.scrollIntoView({ behavior: 'smooth', block: 'start' })
            }
            
            // Set validation highlights and display guide toast
            const errors = {
                jobDescription: !hasJobDesc,
                profile: !hasProfile
            }
            setValidationErrors(errors)
            showToast('Please provide a target job description and either a resume or self-description in the workspace.', 'warning')
        }
    }

    // Handle incoming file (from either standard input or drag-drop)
    const handleFile = (file) => {
        if (file.type === "application/pdf" || file.type === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" || file.name.endsWith(".pdf") || file.name.endsWith(".docx")) {
            if (file.size <= 5 * 1024 * 1024) {
                setSelectedFile(file)
                setFileUpdatedTime(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))
                setValidationErrors((prev) => ({ ...prev, profile: false }))
                showToast(`Resume "${file.name}" uploaded successfully.`, 'success')
            } else {
                showToast("File size exceeds 5MB limit.", "error")
            }
        } else {
            showToast("Invalid file type. Please upload a PDF or DOCX file.", "warning")
        }
    }

    const handleFileChange = (e) => {
        if (e.target.files && e.target.files[0]) {
            handleFile(e.target.files[0])
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
        <div className='home-page-container'>
            {/* Immersive mesh glow elements in the background */}
            <div className='mesh-glow mesh-glow--magenta' />
            <div className='mesh-glow mesh-glow--teal' />

            {/* Floating Capsule Top Navigation Bar */}
            <nav className={`floating-navbar ${mobileMenuOpen ? 'mobile-open' : ''}`}>
                <div className="nav-top-row">
                    <div className='nav-brand' onClick={() => navigate('/')}>
                        <div className='brand-glow-dot' />
                        <span className='brand-text-main'>Interview<span className='brand-text-accent'> Copilot</span></span>
                    </div>

                    {/* Hamburger Button for Mobile floating capsule */}
                    <button 
                        type="button"
                        className={`floating-hamburger ${mobileMenuOpen ? 'active' : ''}`}
                        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                        aria-label="Toggle navigation menu"
                    >
                        <span className="hamburger-line"></span>
                        <span className="hamburger-line"></span>
                        <span className="hamburger-line"></span>
                    </button>
                </div>

                <div className='nav-center-links'>
                    <a href='#workspace' onClick={(e) => { handleScrollTo(e, 'workspace'); setMobileMenuOpen(false); }} className='nav-link'>Workspace</a>
                    <a href='#plans' onClick={(e) => { handleScrollTo(e, 'plans'); setMobileMenuOpen(false); }} className='nav-link'>Recent Plans</a>
                </div>

                <div className='nav-actions'>
                    <span className='nav-user-greeting'>Hi, {user?.username || 'Candidate'}</span>
                    <button type="button" className='nav-cta-btn' onClick={(e) => { handleNavbarGenerateReport(e); setMobileMenuOpen(false); }}>
                        Generate Report
                    </button>
                    <button type="button" className='nav-logout-btn' onClick={handleLogout} title="Logout">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                            <polyline points="16 17 21 12 16 7"></polyline>
                            <line x1="21" y1="12" x2="9" y2="12"></line>
                        </svg>
                    </button>
                </div>
            </nav>

            {/* Centered Platform Introduction Block */}
            <header className='hero-intro-section'>
                <div className='built-for-maang-badge'>
                    <span className='pulsing-indicator-core' />
                    <span className='badge-text-content'>✨ Built for Tech Candidates Targeting MAANG</span>
                </div>

                <h1 className='main-hero-title'>
                    Interview<span className='gradient-accent-text'> Copilot</span>
                    <span className='sub-hero-title'>AI Super-Agent for Tech Candidates</span>
                </h1>

                <p className='emotional-subheadline-copy'>
                    The ultimate intelligent co-pilot for your job search. Plan, predict, and conquer the entire interview funnel with real-time AI strategic roadmaps and interactive simulation.
                </p>

                {/* North Star Metric Card */}
                <div className='north-star-metrics-container'>
                    <div className='metric-pill-item'>
                        <span className='metric-number-val'>94.2%</span>
                        <span className='metric-desc-label'>Candidate Success Rate</span>
                    </div>
                    <div className='metrics-vertical-separator' />
                    <div className='metric-pill-item'>
                        <span className='metric-number-val'>4.8x</span>
                        <span className='metric-desc-label'>MAANG Offers Rate</span>
                    </div>
                    <div className='metrics-vertical-separator' />
                    <div className='metric-pill-item'>
                        <span className='metric-number-val'>+42%</span>
                        <span className='metric-desc-label'>Avg Salary Hike</span>
                    </div>
                </div>
            </header>

            {/* Centered & Wide macOS Preview Workspace (No longer in sidebar split) */}
            <section className='hero-workspace-section' id='workspace'>
                <div className='macos-mock-window'>
                    {/* macOS Window Header Bar */}
                    <div className='macos-header-bar'>
                        <div className='macos-window-controls'>
                            <span className='control-circle control-circle--close' />
                            <span className='control-circle control-circle--minimize' />
                            <span className='control-circle control-circle--maximize' />
                        </div>
                        <span className='macos-window-title'>interviewcopilot_workspace.sh</span>
                    </div>

                    {/* Interactive Form Panel Container */}
                    <div className='macos-window-content'>
                        {/* Component 1: IDE Code Editor Job Description */}
                        <div className='code-editor-pane'>
                            <div className='editor-tab-header'>
                                <div className='tab-capsule active'>
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ marginRight: '6px' }}>
                                        <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
                                        <line x1="9" y1="3" x2="9" y2="21" />
                                    </svg>
                                    target_job_description.md
                                </div>
                                <span className='required-badge'>Required</span>
                            </div>
                            <div className='editor-textarea-wrapper'>
                                <div className='editor-line-numbers'>
                                    <span>01</span>
                                    <span>02</span>
                                    <span>03</span>
                                    <span>04</span>
                                    <span>05</span>
                                    <span>06</span>
                                    <span>07</span>
                                </div>
                                <textarea
                                    value={jobDescription}
                                    onChange={(e) => {
                                        setJobDescription(e.target.value)
                                        if (e.target.value.trim() !== "") {
                                            setValidationErrors((prev) => ({ ...prev, jobDescription: false }))
                                        }
                                    }}
                                    className={`editor-textarea-control ${validationErrors.jobDescription ? 'editor-textarea-control--error' : ''}`}
                                    placeholder={`Paste the target job description here...\ne.g. 'Senior Frontend Engineer at Google requires proficiency in React, TypeScript, and large-scale system design...'`}
                                    maxLength={5000}
                                />
                            </div>
                            <div className='editor-char-counter-panel'>
                                <span>{jobDescription.length} / 5000 characters</span>
                            </div>
                        </div>

                        {/* Component 2: Drag and drop Profile Upload */}
                        <div className='profile-workspace-pane'>
                            <div className='pane-label-title'>Your Profile</div>

                            <div className='drag-drop-upload-container'>
                                {selectedFile ? (
                                    <div className='premium-uploaded-file-card'>
                                        <div className='uploaded-card-icon-glow'>
                                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                                                <polyline points="14 2 14 8 20 8"></polyline>
                                                <line x1="16" y1="13" x2="8" y2="13"></line>
                                                <line x1="16" y1="17" x2="8" y2="17"></line>
                                            </svg>
                                        </div>
                                        <div className='uploaded-card-text-details'>
                                            <p className='uploaded-file-display-name'>{selectedFile.name}</p>
                                            <p className='uploaded-file-display-meta'>
                                                {(selectedFile.size / 1024 / 1024).toFixed(2)} MB &bull; Ready to process
                                            </p>
                                        </div>
                                        <div className='uploaded-card-action-states'>
                                            <span className='uploaded-status-badge'>
                                                <span className='uploaded-status-badge__glowing-dot' />
                                                Ready
                                            </span>
                                            <button
                                                type="button"
                                                className='uploaded-remove-action-btn'
                                                onClick={handleRemoveFile}
                                                title="Remove resume"
                                            >
                                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                    <line x1="18" y1="6" x2="6" y2="18"></line>
                                                    <line x1="6" y1="6" x2="18" y2="18"></line>
                                                </svg>
                                            </button>
                                        </div>
                                    </div>
                                ) : (
                                    <label 
                                        className={`premium-glassmorphic-dropzone ${dragActive ? 'premium-glassmorphic-dropzone--active' : ''} ${validationErrors.profile ? 'premium-glassmorphic-dropzone--error' : ''}`}
                                        htmlFor='resume'
                                        onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
                                        onDragLeave={() => setDragActive(false)}
                                        onDrop={(e) => {
                                            e.preventDefault()
                                            setDragActive(false)
                                            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                                                handleFile(e.dataTransfer.files[0])
                                            }
                                        }}
                                    >
                                        <span className='dropzone-neon-upload-icon'>
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                                                <polyline points="17 8 12 3 7 8" />
                                                <line x1="12" y1="3" x2="12" y2="15" />
                                            </svg>
                                        </span>
                                        <p className='dropzone-primary-headline'>Drag &amp; drop resume or click to upload</p>
                                        <p className='dropzone-secondary-subline'>PDF or DOCX format (Max 5MB)</p>
                                        <input
                                            ref={resumeInputRef}
                                            hidden
                                            type='file'
                                            id='resume'
                                            name='resume'
                                            accept='.pdf,.docx'
                                            onChange={handleFileChange}
                                        />
                                    </label>
                                )}
                            </div>

                            {/* Minimal OR Divider */}
                            <div className='profile-split-divider'>
                                <span>OR</span>
                            </div>

                            {/* Textarea Profile Description */}
                            <div className='self-description-form-group'>
                                <textarea
                                    value={selfDescription}
                                    onChange={(e) => {
                                        setSelfDescription(e.target.value)
                                        if (e.target.value.trim() !== "") {
                                            setValidationErrors((prev) => ({ ...prev, profile: false }))
                                        }
                                    }}
                                    id='selfDescription'
                                    name='selfDescription'
                                    className={`quick-description-textarea ${validationErrors.profile ? 'quick-description-textarea--error' : ''}`}
                                    placeholder="Quick self-description: outline your years of experience, core tech stack, and notable achievements if you don't have a resume file..."
                                />
                            </div>

                            <div className='profile-requirement-info-banner'>
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginRight: '6px', flexShrink: 0 }}>
                                    <circle cx="12" cy="12" r="10" />
                                    <line x1="12" y1="16" x2="12" y2="12" />
                                    <line x1="12" y1="8" x2="12.01" y2="8" />
                                </svg>
                                <span>Either a <strong>Resume</strong> or <strong>Self Description</strong> is required to generate custom blueprints.</span>
                            </div>
                        </div>

                        {/* macOS Window Form Actions Footer */}
                        <div className='macos-footer-form-actions'>
                            <span className='macos-eta-badge'>⚡ AI blueprint synthesis &bull; ~30s</span>
                            <button
                                type="button"
                                onClick={handleGenerateReport}
                                className='macos-synthesis-submit-btn'
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ marginRight: '6px' }}>
                                    <polygon points="12 2 2 22 12 17 22 22 12 2" />
                                </svg>
                                Generate My Interview Strategy
                            </button>
                        </div>
                    </div>
                </div>
            </section>

            {/* Bottom Section: Recent Interview Plans Grid */}
            <section className='recent-plans-history-section' id='plans'>
                <div className='plans-history-header-block'>
                    <h2 className='plans-history-title'>My Recent Interview Plans</h2>
                    <p className='plans-history-subtitle'>Review and track your previously synthesized custom strategy blueprints.</p>
                </div>

                {reports.length > 0 ? (
                    <div className='glass-plans-cards-grid'>
                        {reports.map(report => (
                            <div 
                                key={report._id} 
                                className='glass-plan-card-item' 
                                onClick={() => navigate(`/interview/${report._id}`)}
                            >
                                <div className='card-glow-reflection-effect' />
                                <div className='card-inner-details'>
                                    <div className='card-title-row'>
                                        <h3>{report.title || 'Untitled Position'}</h3>
                                        <span className='arrow-pointer'>→</span>
                                    </div>
                                    <p className='card-created-date'>Generated on {new Date(report.createdAt).toLocaleDateString()}</p>
                                    <div className='card-status-match-row'>
                                        <span className='match-score-badge'>
                                            Match Score: <strong className={`match-score-figure ${report.matchScore >= 80 ? 'match-score-figure--high' : report.matchScore >= 60 ? 'match-score-figure--mid' : 'match-score-figure--low'}`}>{report.matchScore}%</strong>
                                        </span>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div className='glassmorphic-empty-state-card'>
                        <div className='empty-state-icon-backdrop'>
                            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                                <line x1="8" y1="21" x2="16" y2="21"></line>
                                <line x1="12" y1="17" x2="12" y2="21"></line>
                            </svg>
                        </div>
                        <h3>No interview strategies yet</h3>
                        <p>Complete the workspace form details above to synthesize your very first high-impact AI strategy report.</p>
                    </div>
                )}
            </section>

            {/* Premium Immersive Page Footer */}
            <footer className='premium-page-footer-links'>
                <div className='footer-links-row'>
                    <a href='#' className='footer-link-item'>Privacy Policy</a>
                    <span className='footer-links-bullet'>&bull;</span>
                    <a href='#' className='footer-link-item'>Terms of Service</a>
                    <span className='footer-links-bullet'>&bull;</span>
                    <a href='#' className='footer-link-item'>Help Center</a>
                </div>
                <p className='footer-copyright-text'>&copy; {new Date().getFullYear()} Interview Copilot. All rights reserved.</p>
            </footer>
        </div>
    )
}

export default Home