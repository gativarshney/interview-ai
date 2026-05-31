import React, { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useInterview } from '../hooks/useInterview'
import useAuth from '../../auth/hooks/useAuth'
import { useToast } from '../components/Toast'
import ResumePdfModal from '../components/ResumePdfModal'

const Dashboard = () => {
    const { loading, reports, getReports, getResumePdf, pdfGenerating } = useInterview()
    const { user, handleLogout } = useAuth()
    const { showToast } = useToast()
    const navigate = useNavigate()
    const [sidebarOpen, setSidebarOpen] = useState(false)

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
        <div className="dashboard-layout-container">
            {/* Sidebar backdrop overlay on mobile */}
            <div 
                className={`sidebar-overlay ${sidebarOpen ? 'show' : ''}`} 
                onClick={() => setSidebarOpen(false)}
            />

            {/* Mobile Top Bar */}
            <header className="mobile-dashboard-header">
                <button 
                    type="button"
                    className="mobile-menu-toggle-btn"
                    onClick={() => setSidebarOpen(true)}
                    aria-label="Toggle sidebar menu"
                >
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="3" y1="12" x2="21" y2="12"></line>
                        <line x1="3" y1="6" x2="21" y2="6"></line>
                        <line x1="3" y1="18" x2="21" y2="18"></line>
                    </svg>
                </button>
                <div className="mobile-header-brand" onClick={() => navigate('/')}>
                    <div className="brand-dot" />
                    <span>Interview Copilot</span>
                </div>
                <div className="mobile-header-actions">
                    <button type="button" className="mobile-new-btn" onClick={() => navigate('/generate')} title="New Strategy">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                    </button>
                </div>
            </header>

            {/* Glassmorphic Left Sidebar */}
            <aside className={`dashboard-sidebar ${sidebarOpen ? 'open' : ''}`}>
                <div className="sidebar-brand-wrapper">
                    <div className="sidebar-brand" onClick={() => { navigate('/'); setSidebarOpen(false); }}>
                        <div className="brand-dot" />
                        <span>Interview Copilot</span>
                    </div>
                    {/* Mobile close sidebar button */}
                    <button 
                        type="button"
                        className="mobile-sidebar-close-btn"
                        onClick={() => setSidebarOpen(false)}
                        aria-label="Close sidebar"
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                            <line x1="18" y1="6" x2="6" y2="18"></line>
                            <line x1="6" y1="6" x2="18" y2="18"></line>
                        </svg>
                    </button>
                </div>

                <button className="sidebar-action-btn" onClick={() => { navigate('/generate'); setSidebarOpen(false); }}>
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                    New Strategy
                </button>

                <nav className="sidebar-nav">
                    <button className="sidebar-nav-link active" onClick={() => { navigate('/dashboard'); setSidebarOpen(false); }}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                        Dashboard
                    </button>
                    <button className="sidebar-nav-link" onClick={() => { navigate('/generate'); setSidebarOpen(false); }}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                        7-Day Roadmap
                    </button>
                    <button className="sidebar-nav-link" onClick={() => { handleDownloadResume(); setSidebarOpen(false); }}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                        ATS Resume Downloader
                    </button>
                    <button className="sidebar-nav-link" onClick={() => { triggerMockAlert(); setSidebarOpen(false); }}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                        Mock Practice
                    </button>
                </nav>

                <div className="sidebar-recents">
                    <span className="recents-header">Recent Strategies</span>
                    <div className="recents-list">
                        {reports && reports.length > 0 ? (
                            reports.slice(0, 4).map(r => (
                                <button key={r._id} className="recent-item-link" onClick={() => { navigate(`/interview/${r._id}`); setSidebarOpen(false); }}>
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
                    <button className="logout-icon-btn" onClick={() => { handleLogout(); setSidebarOpen(false); }} title="Logout">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                    </button>
                </div>
            </aside>

            {/* Main Interactive Workspace Area */}
            <main className="dashboard-main-content">
                <header className="workspace-header">
                    <div className="header-breadcrumbs">
                        <span>Coach</span>
                        <span className="breadcrumb-separator">/</span>
                        <span className="breadcrumb-active">Ask anything</span>
                    </div>
                    <div className="header-search-bar">
                        <input type="text" placeholder="Search strategies or target roles..." />
                        <svg className="search-icon" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                    </div>
                </header>

                {/* Copilot Prompt Section */}
                <section className="copilot-prompt-hero">
                    <div className="copilot-tag">Your AI Interview Coach</div>
                    
                    <h1 className="copilot-title">
                        Where should <span className="highlight-text-gradient">we start?</span>
                    </h1>
                    
                    <p className="copilot-subtitle">
                        Your FAANG-grade prep companion. Optimize your resume keyword alignment, synthesize dynamic daily study roadmaps, or practice targeted mock questions.
                    </p>

                    {/* Highly Polished Floating Prompt Box */}
                    <div className="copilot-input-container">
                        <div className="copilot-input-wrapper">
                            <span className="input-indicator">|</span>
                            <input 
                                type="text" 
                                placeholder="Ask Coach to analyze your target role or optimize keywords..." 
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter') navigate('/generate');
                                }}
                            />
                            <div className="input-actions">
                                <span className="action-tag">Build</span>
                                <button className="submit-prompt-btn" onClick={() => navigate('/generate')}>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* Dynamic Suggestion Chips */}
                    <div className="copilot-quick-chips">
                        <button className="chip-btn" onClick={() => navigate('/generate')}>Optimize Resume</button>
                        <button className="chip-btn" onClick={triggerMockAlert}>Start Mock Interview</button>
                        <button className="chip-btn" onClick={() => navigate('/generate')}>Draft 7-Day Roadmap</button>
                        <button className="chip-btn" onClick={handleDownloadResume}>Download ATS PDF</button>
                        <button className="chip-btn" onClick={triggerMockAlert}>Analyze Skill Gaps</button>
                    </div>
                </section>

                {/* KPI metrics row */}
                <section className="dashboard-metrics">
                    <div className="metric-card">
                        <div className="metric-card__info">
                            <span className="metric-label">Completed Blueprints</span>
                            <h3 className="metric-value">{stats.completed}</h3>
                            <span className="metric-subtext">AI-generated plans</span>
                        </div>
                        <div className="metric-card__icon">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                        </div>
                    </div>

                    <div className="metric-card">
                        <div className="metric-card__info">
                            <span className="metric-label">Resume matching</span>
                            <h3 className="metric-value" style={{ fontSize: stats.hasResume ? '0.95rem' : '1.5rem', fontWeight: 700, wordBreak: 'break-all' }}>
                                {stats.hasResume ? stats.resumeName : 'Not Uploaded'}
                            </h3>
                            <span className="metric-subtext">
                                {stats.hasResume ? (
                                    <>
                                        <span className="pulse-dot" />
                                        ATS Optimized
                                    </>
                                ) : (
                                    'Upload to unlock scores'
                                )}
                            </span>
                        </div>
                        <div className="metric-card__icon metric-card__icon--accent">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                        </div>
                    </div>

                    <div className="metric-card">
                        <div className="metric-card__info">
                            <span className="metric-label">Latest Match Rating</span>
                            <h3 className="metric-value">
                                {stats.latestScore !== null ? `${stats.latestScore}%` : '—'}
                            </h3>
                            <span className="metric-subtext">ATS Keyword Fit</span>
                        </div>
                        <div className="metric-card__icon">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
                        </div>
                    </div>
                </section>

                {/* Workspace grid details */}
                <div className="dashboard-grid">
                    
                    {/* Recent Plans Card */}
                    <div className="dash-card">
                        <div className="dash-card__header">
                            <h2>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                                Recent Blueprints & Strategies
                            </h2>
                        </div>

                        {loading ? (
                            <p style={{ color: '#7d8590', fontStyle: 'italic', fontSize: '0.85rem' }}>Loading recent strategies...</p>
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
                            <p style={{ color: '#7d8590', fontStyle: 'italic', fontSize: '0.85rem', margin: 0 }}>
                                No strategies created yet. click "New Strategy" on the sidebar or type a prompt above to get started.
                            </p>
                        )}
                    </div>

                    <div className="dashboard-grid-right-col">
                        {/* Skill Insights widget */}
                        <div className="dash-card">
                            <div className="dash-card__header">
                                <h2>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 2 22 22 22"></polygon><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                                    Skill Gap Audit
                                </h2>
                            </div>
                            <div className="skill-insights-widget">
                                <div className="insight-section">
                                    <h3>Core Strengths</h3>
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

                        {/* Recommended Actions */}
                        <div className="dash-card recommended-action-card">
                            <div className="card-accent-line" />
                            <div className="dash-card__header" style={{ border: 'none', padding: 0 }}>
                                <h2 style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#ff2d78' }}>
                                    Coach Recommendation
                                </h2>
                            </div>
                            <div className="recommended-action-card__body">
                                <h3 className="action-title">{recommendedAction.title}</h3>
                                <p className="action-text">{recommendedAction.text}</p>
                            </div>
                            <button className="cta-btn" onClick={recommendedAction.action}>
                                {recommendedAction.btnText}
                                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                            </button>
                        </div>
                    </div>
                </div>
            </main>
            
            {/* Download Progress Modal Overlay */}
            <ResumePdfModal />
        </div>
    );
}

export default Dashboard;
