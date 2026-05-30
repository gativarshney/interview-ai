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
        <div className='home-page'>

            {/* Page Header */}
            <header className='page-header'>
                <h1>Create Your Custom <span className='highlight'>Interview Plan</span></h1>
                <p>Welcome back, <strong>{user?.username || 'Candidate'}</strong>! Let our AI analyze the job requirements and your unique profile to build a winning strategy.</p>
            </header>

            {/* Main Card */}
            <div className='interview-card'>
                <div className='interview-card__body'>

                    {/* Left Panel - Job Description */}
                    <div className='panel panel--left'>
                        <div className='panel__header'>
                            <span className='panel__icon'>
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2" /><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" /></svg>
                            </span>
                            <h2>Target Job Description</h2>
                            <span className='badge badge--required'>Required</span>
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
                        <div className='char-counter'>{jobDescription.length} / 5000 chars</div>
                    </div>

                    {/* Vertical Divider */}
                    <div className='panel-divider' />

                    {/* Right Panel - Profile */}
                    <div className='panel panel--right'>
                        <div className='panel__header'>
                            <span className='panel__icon'>
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                            </span>
                            <h2>Your Profile</h2>
                        </div>

                        {/* Upload Resume */}
                        <div className='upload-section'>
                            <label className='section-label'>
                                Upload Resume
                                <span className='badge badge--best'>Best Results</span>
                            </label>

                            {selectedFile ? (
                                <div className='uploaded-file-card'>
                                    <div className='uploaded-file-card__icon'>
                                        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                                    </div>
                                    <div className='uploaded-file-card__details'>
                                        <p className='uploaded-file-card__name'>{selectedFile.name}</p>
                                        <p className='uploaded-file-card__meta'>
                                            {(selectedFile.size / 1024 / 1024).toFixed(2)} MB &bull; Uploaded
                                        </p>
                                        <p className='uploaded-file-card__date'>
                                            Last updated: {fileUpdatedTime}
                                        </p>
                                    </div>
                                    <div className='uploaded-file-card__status'>
                                        <span className='status-badge'>
                                            <span className='status-badge__dot'></span>
                                            Ready
                                        </span>
                                        <button
                                            type="button"
                                            className='remove-file-btn'
                                            onClick={handleRemoveFile}
                                            title="Remove resume"
                                        >
                                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <label className={`dropzone ${validationErrors.profile ? 'dropzone--error' : ''}`} htmlFor='resume'>
                                    <span className='dropzone__icon'>
                                        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 16 12 12 8 16" /><line x1="12" y1="12" x2="12" y2="21" /><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3" /></svg>
                                    </span>
                                    <p className='dropzone__title'>Click to upload or drag &amp; drop</p>
                                    <p className='dropzone__subtitle'>PDF or DOCX (Max 5MB)</p>
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

                        {/* OR Divider */}
                        <div className='or-divider'><span>OR</span></div>

                        {/* Quick Self-Description */}
                        <div className='self-description'>
                            <label className='section-label' htmlFor='selfDescription'>Quick Self-Description</label>
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
                                className={`panel__textarea panel__textarea--short ${validationErrors.profile ? 'panel__textarea--error' : ''}`}
                                placeholder="Briefly describe your experience, key skills, and years of experience if you don't have a resume handy..."
                            />
                        </div>

                        {/* Info Box */}
                        <div className='info-box'>
                            <span className='info-box__icon'>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" stroke="#1a1f27" strokeWidth="2" /><line x1="12" y1="16" x2="12.01" y2="16" stroke="#1a1f27" strokeWidth="2" /></svg>
                            </span>
                            <p>Either a <strong>Resume</strong> or a <strong>Self Description</strong> is required to generate a personalized plan.</p>
                        </div>
                    </div>
                </div>

                {/* Card Footer */}
                <div className='interview-card__footer'>
                    <span className='footer-info'>AI-Powered Strategy Generation &bull; Approx 30s</span>
                    <button
                        onClick={handleGenerateReport}
                        className='generate-btn'>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z" /></svg>
                        Generate My Interview Strategy
                    </button>
                </div>
            </div>

            {/* Recent Reports List */}
            <section className='recent-reports'>
                <h2>My Recent Interview Plans</h2>
                {reports.length > 0 ? (
                    <ul className='reports-list'>
                        {reports.map(report => (
                            <li key={report._id} className='report-item' onClick={() => navigate(`/interview/${report._id}`)}>
                                <h3>{report.title || 'Untitled Position'}</h3>
                                <p className='report-meta'>Generated on {new Date(report.createdAt).toLocaleDateString()}</p>
                                <p className={`match-score ${report.matchScore >= 80 ? 'score--high' : report.matchScore >= 60 ? 'score--mid' : 'score--low'}`}>Match Score: {report.matchScore}%</p>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <div className='empty-state-card'>
                        <div className='empty-state-card__icon'>
                            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                        </div>
                        <h3>No interview strategies yet</h3>
                        <p>Complete the form above to generate your first personalized AI interview blueprint.</p>
                    </div>
                )}
            </section>

            {/* Page Footer */}
            <footer className='page-footer'>
                <a href='#'>Privacy Policy</a>
                <a href='#'>Terms of Service</a>
                <a href='#'>Help Center</a>
            </footer>
        </div>
    )
}

export default Home