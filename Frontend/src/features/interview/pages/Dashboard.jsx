import React, { useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useInterview } from '../hooks/useInterview'
import useAuth from '../../auth/hooks/useAuth'
import { useToast } from '../components/Toast'

const Dashboard = () => {
    const { loading, reports, getReports, getResumePdf } = useInterview()
    const { user, handleLogout } = useAuth()
    const { showToast } = useToast()
    const navigate = useNavigate()

    useEffect(() => {
        getReports()
    }, [])

    const latestReport = useMemo(() => {
        return reports && reports.length > 0 ? reports[0] : null
    }, [reports])

    // Aggregate statistics
    const stats = useMemo(() => {
        const completed = reports ? reports.length : 0
        const hasResume = latestReport && latestReport.resumeFilename ? true : false
        const resumeName = latestReport && latestReport.resumeFilename ? latestReport.resumeFilename : 'No resume uploaded'
        const latestScore = latestReport && latestReport.matchScore ? latestReport.matchScore : null

        return {
            completed,
            hasResume,
            resumeName,
            latestScore
        }
    }, [reports, latestReport])

    // Aggregate skill insights
    const skillInsights = useMemo(() => {
        if (!reports || reports.length === 0) {
            return { strong: [], gapsHigh: [], gapsMedium: [], gapsLow: [] }
        }

        // Collect all gaps
        const gapsMap = {}
        reports.forEach(r => {
            if (r.skillGaps && Array.isArray(r.skillGaps)) {
                r.skillGaps.forEach(g => {
                    const skillName = g.skill.trim()
                    const severity = g.severity || 'medium'
                    gapsMap[skillName] = severity
                })
            }
        })

        const gapsHigh = []
        const gapsMedium = []
        const gapsLow = []

        Object.entries(gapsMap).forEach(([skill, severity]) => {
            if (severity === 'high') gapsHigh.push(skill)
            else if (severity === 'medium') gapsMedium.push(skill)
            else gapsLow.push(skill)
        })

        // Generate strong skills placeholder dynamically (excluding high/medium gaps)
        const commonStrong = ['Problem Solving', 'Git', 'System Design', 'RESTful APIs', 'JavaScript', 'Communication']
        const strong = commonStrong.filter(s => !gapsHigh.includes(s) && !gapsMedium.includes(s))

        return {
            strong: strong.slice(0, 4),
            gapsHigh: gapsHigh.slice(0, 3),
            gapsMedium: gapsMedium.slice(0, 3),
            gapsLow: gapsLow.slice(0, 3)
        }
    }, [reports])

    // Smart Recommended Next Action
    const recommendedAction = useMemo(() => {
        if (!reports || reports.length === 0) {
            return {
                title: 'Synthesize Your First Strategy',
                text: 'You haven\'t created any interview strategies yet. Connect your profile and target role to generate a personalized 7-day preparation blueprint.',
                btnText: 'Generate Strategy',
                action: () => navigate('/generate')
            }
        }

        if (!stats.hasResume) {
            return {
                title: 'Optimize ATS Resume Matching',
                text: 'Your recent strategy plan was generated from a quick self-description. Upload a full resume PDF to unlock custom ATS keyword scores and layout audits.',
                btnText: 'Upload Resume Strategy',
                action: () => navigate('/generate')
            }
        }

        return {
            title: `Master your ${latestReport.title} prep`,
            text: `Your latest alignment score is ${stats.latestScore}%. Study the Day-by-Day road map and practice your targeted technical challenges to resolve the severe gaps.`,
            btnText: 'View 7-Day Roadmap',
            action: () => navigate(`/interview/${latestReport._id}`)
        }
    }, [reports, stats, latestReport, navigate])

    const handleDownloadResume = () => {
        if (latestReport) {
            getResumePdf(latestReport._id)
        } else {
            showToast('Please generate an interview plan with a resume first to compile a PDF.', 'warning')
        }
    }

    const triggerMockAlert = () => {
        showToast('Advanced interactive mock simulator coming soon in Phase 7!', 'info')
    }

    return (
        <div className="dashboard-page">
            
            {/* Welcome Banner */}
            <div className="dashboard-welcome">
                <div className="welcome-glow" />
                <button className="logout-btn-header" onClick={handleLogout}>
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                    Logout
                </button>
                <h1>Welcome Back, {user?.username || 'Candidate'}</h1>
                <p>Track your preparation milestones, check ATS resume alignment statistics, and refine core competencies to clear FAANG-level engineering interviews.</p>
            </div>

            {/* Metrics Row */}
            <div className="dashboard-metrics">
                
                {/* Metric: Completed */}
                <div className="metric-card">
                    <div className="metric-card__info">
                        <span className="metric-label">Completed Plans</span>
                        <h3 className="metric-value">{stats.completed}</h3>
                        <span className="metric-subtext">AI-generated blueprints</span>
                    </div>
                    <div className="metric-card__icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                    </div>
                </div>

                {/* Metric: Resume */}
                <div className="metric-card">
                    <div className="metric-card__info">
                        <span className="metric-label">Resume Status</span>
                        <h3 className="metric-value" style={{ fontSize: stats.hasResume ? '1.1rem' : '1.75rem', fontWeight: 700, wordBreak: 'break-all' }}>
                            {stats.hasResume ? stats.resumeName : 'Not Uploaded'}
                        </h3>
                        <span className="metric-subtext">
                            {stats.hasResume ? (
                                <>
                                    <span className="pulse-dot" />
                                    Active for ATS audits
                                </>
                            ) : (
                                'Upload PDF for optimal scores'
                            )}
                        </span>
                    </div>
                    <div className="metric-card__icon metric-card__icon--accent">
                        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                    </div>
                </div>

                {/* Metric: Match Score */}
                <div className="metric-card">
                    <div className="metric-card__info">
                        <span className="metric-label">Latest Match Score</span>
                        <h3 className="metric-value">
                            {stats.latestScore !== null ? `${stats.latestScore}%` : '—'}
                        </h3>
                        <span className="metric-subtext">ATS alignment rating</span>
                    </div>
                    <div className="metric-card__icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
                    </div>
                </div>
            </div>

            {/* Dashboard Grid */}
            <div className="dashboard-grid">
                
                {/* Column Left: Recent Reports & Skills */}
                <div className="dashboard-col-left">
                    
                    {/* Recent Plans Card */}
                    <div className="dash-card">
                        <div className="dash-card__header">
                            <h2>
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                                Recent Strategies
                            </h2>
                        </div>

                        {loading ? (
                            <p style={{ color: '#7d8590', fontStyle: 'italic', fontSize: '0.9rem' }}>Loading recent strategies...</p>
                        ) : reports && reports.length > 0 ? (
                            <div className="dash-reports-list">
                                {reports.map(r => (
                                    <div 
                                        key={r._id} 
                                        className="dash-report-row"
                                        onClick={() => navigate(`/interview/${r._id}`)}
                                    >
                                        <div className="dash-report-row__main">
                                            <h3>{r.title || 'Untitled Position'}</h3>
                                            <div className="meta-details">
                                                <span>{new Date(r.createdAt).toLocaleDateString()}</span>
                                                <span className="dot-divider" />
                                                {r.resumeFilename ? (
                                                    <span className="file-tag">
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                                                        {r.resumeFilename}
                                                    </span>
                                                ) : (
                                                    <span>Profile description</span>
                                                )}
                                            </div>
                                        </div>
                                        <div className="dash-report-row__score">
                                            <span className={`score-badge ${r.matchScore >= 80 ? 'score-badge--high' : r.matchScore >= 60 ? 'score-badge--mid' : 'score-badge--low'}`}>
                                                Match: {r.matchScore}%
                                            </span>
                                            <span className="row-arrow">
                                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                            </span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <p style={{ color: '#7d8590', fontStyle: 'italic', fontSize: '0.9rem', margin: 0 }}>
                                No strategies created yet. Get started by clicking "Generate Strategy Blueprint" on the right panel.
                            </p>
                        )}
                    </div>
                </div>

                {/* Column Right: Smart Action & Quick Actions */}
                <div className="dashboard-col-right">
                    
                    {/* Recommended Next Action */}
                    <div className="dash-card recommended-action-card">
                        <div className="card-accent-line" />
                        <div className="dash-card__header" style={{ border: 'none', padding: 0 }}>
                            <h2 style={{ fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#ff2d78' }}>
                                Recommended Next Action
                            </h2>
                        </div>
                        <div className="recommended-action-card__body">
                            <h3 className="action-title">{recommendedAction.title}</h3>
                            <p className="action-text">{recommendedAction.text}</p>
                        </div>
                        <button className="cta-btn" onClick={recommendedAction.action}>
                            {recommendedAction.btnText}
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                        </button>
                    </div>

                    {/* Skill Insights */}
                    <div className="dash-card">
                        <div className="dash-card__header">
                            <h2>
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 2 22 22 22"></polygon><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                                Skill Insights
                            </h2>
                        </div>
                        <div className="skill-insights-widget">
                            
                            {/* Strongest Skills */}
                            <div className="insight-section">
                                <h3>Core Demonstrated Strengths</h3>
                                <div className="skills-list">
                                    {skillInsights.strong.length > 0 ? (
                                        skillInsights.strong.map((s, idx) => (
                                            <span key={idx} className="skill-chip skill-chip--strong">{s}</span>
                                        ))
                                    ) : (
                                        <p className="no-skills-msg">Analyze a plan to extract strengths.</p>
                                    )}
                                </div>
                            </div>

                            {/* Weakest Skills / High Severity Gaps */}
                            <div className="insight-section">
                                <h3>High Severity Gaps</h3>
                                <div className="skills-list">
                                    {skillInsights.gapsHigh.length > 0 ? (
                                        skillInsights.gapsHigh.map((s, idx) => (
                                            <span key={idx} className="skill-chip skill-chip--weak-high">{s}</span>
                                        ))
                                    ) : skillInsights.gapsMedium.length > 0 ? (
                                        skillInsights.gapsMedium.map((s, idx) => (
                                            <span key={idx} className="skill-chip skill-chip--weak-medium">{s}</span>
                                        ) )
                                    ) : (
                                        <p className="no-skills-msg">No critical skill gaps detected.</p>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Quick Actions Panel */}
                    <div className="dash-card">
                        <div className="dash-card__header">
                            <h2>
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="4"></circle><line x1="4.93" y1="4.93" x2="9.17" y2="9.17"></line><line x1="19.07" y1="4.93" x2="14.83" y2="9.17"></line><line x1="14.83" y1="14.83" x2="19.07" y2="19.07"></line><line x1="9.17" y1="14.83" x2="4.93" y2="19.07"></line></svg>
                                Quick Actions
                            </h2>
                        </div>
                        <div className="quick-actions-grid">
                            <button className="action-btn action-btn--primary" onClick={() => navigate('/generate')}>
                                <span className="action-btn__icon">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                                </span>
                                Generate Strategy Blueprint
                            </button>
                            <button className="action-btn" onClick={handleDownloadResume}>
                                <span className="action-btn__icon">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="8 17 12 21 16 17"></polyline><line x1="12" y1="12" x2="12" y2="21"></line><path d="M20.88 18.09A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.29"></path></svg>
                                </span>
                                Generate Premium Resume
                            </button>
                            <button className="action-btn" onClick={triggerMockAlert}>
                                <span className="action-btn__icon">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                                </span>
                                Practice Behavioral Mock
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default Dashboard
