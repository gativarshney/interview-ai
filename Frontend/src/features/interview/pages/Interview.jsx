import React, { useState, useEffect } from 'react'
import '../styles/interview.scss'
import { useInterview } from '../hooks/useInterview.js'
import { useParams, useNavigate } from 'react-router-dom'
import LoadingScreen from '../components/LoadingScreen.jsx'
import ResumePdfModal from '../components/ResumePdfModal.jsx'



const NAV_ITEMS = [
    { id: 'technical', label: 'Technical Questions', icon: (<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" /></svg>) },
    { id: 'behavioral', label: 'Behavioral Questions', icon: (<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" /></svg>) },
    { id: 'roadmap', label: 'Road Map', icon: (<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="3 11 22 2 13 21 11 13 3 11" /></svg>) },
]

const MOBILE_NAV_ITEMS = [
    { id: 'technical', label: 'Technical', icon: (<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" /></svg>) },
    { id: 'behavioral', label: 'Behavioral', icon: (<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" /></svg>) },
    { id: 'roadmap', label: 'Road Map', icon: (<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polygon points="3 11 22 2 13 21 11 13 3 11" /></svg>) },
    { id: 'insights', label: 'Insights', icon: (<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>) },
]

// ── Sub-components ────────────────────────────────────────────────────────────
// ── Sub-components ────────────────────────────────────────────────────────────
const QuestionCard = ({ item, index, jobDescription }) => {
    const [ open, setOpen ] = useState(false)
    const [ practiceMode, setPracticeMode ] = useState(false)
    const [ candidateAnswer, setCandidateAnswer ] = useState("")
    const [ evaluating, setEvaluating ] = useState(false)
    const [ feedback, setFeedback ] = useState(null)
    const [ copied, setCopied ] = useState(false)

    const { evaluateAnswer } = useInterview()

    const handleEvaluate = async () => {
        if (!candidateAnswer.trim()) return
        setEvaluating(true)
        try {
            const result = await evaluateAnswer({
                question: item.question,
                answer: candidateAnswer,
                jobDescription: jobDescription || "General job description alignment."
            })
            if (result) {
                setFeedback(result)
            }
        } catch (err) {
            console.error('AI Practice evaluation failed:', err)
        } finally {
            setEvaluating(false)
        }
    }

    const handleCopyRevision = () => {
        if (feedback && feedback.suggestedRevision) {
            navigator.clipboard.writeText(feedback.suggestedRevision)
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
        }
    }

    return (
        <div className='q-card'>
            <div className='q-card__header' onClick={() => setOpen(o => !o)}>
                <span className='q-card__index'>Q{index + 1}</span>
                <p className='q-card__question'>{item.question}</p>
                <span className={`q-card__chevron ${open ? 'q-card__chevron--open' : ''}`}>
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9" /></svg>
                </span>
            </div>
            {open && (
                <div className='q-card__body'>
                    <div className='q-card__section'>
                        <span className='q-card__tag q-card__tag--intention'>Intention</span>
                        <p>{item.intention}</p>
                    </div>
                    <div className='q-card__section'>
                        <span className='q-card__tag q-card__tag--answer'>Model Answer</span>
                        <p>{item.answer}</p>
                    </div>

                    {/* Premium Interactive Mock Practice Section */}
                    <div className='q-practice'>
                        <button
                            type="button"
                            className={`q-practice__toggle-btn ${practiceMode ? 'q-practice__toggle-btn--active' : ''}`}
                            onClick={() => setPracticeMode(p => !p)}
                        >
                            <svg className="q-practice__toggle-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M12 20h9M3 20v-8c0-2.2 1.8-4 4-4h10c2.2 0 4 1.8 4 4v8M3 12h18"/>
                            </svg>
                            {practiceMode ? 'Close Practice Arena' : 'Toggle Practice Mode'}
                        </button>

                        {practiceMode && (
                            <div className='q-practice__container'>
                                <label className='q-practice__label'>Type your practice response below:</label>
                                <textarea
                                    className='q-practice__textarea'
                                    value={candidateAnswer}
                                    onChange={(e) => setCandidateAnswer(e.target.value)}
                                    placeholder="Draft your answer using Situation, Action, and specific business results (STAR method)..."
                                    disabled={evaluating}
                                />

                                <div className='q-practice__actions'>
                                    <button
                                        type="button"
                                        className='q-practice__eval-btn'
                                        onClick={handleEvaluate}
                                        disabled={evaluating || !candidateAnswer.trim()}
                                    >
                                        {evaluating ? (
                                            <>
                                                <span className="q-practice__spinner" />
                                                Synthesizing AI Evaluation...
                                            </>
                                        ) : (
                                            <>
                                                <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style={{ marginRight: '0.4rem' }}>
                                                    <path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z"/>
                                                </svg>
                                                Get AI Recruiter Assessment
                                            </>
                                        )}
                                    </button>
                                </div>

                                {feedback && (
                                    <div className='q-feedback'>
                                        <div className='q-feedback__header'>
                                            <span className='q-feedback__title'>AI Recruiter Assessment</span>
                                            <span className={`rating-badge rating-badge--${feedback.rating.toLowerCase().replace(/\s+/g, '-')}`}>
                                                {feedback.rating}
                                            </span>
                                        </div>

                                        <div className='q-feedback__section'>
                                            <h4 className='q-feedback__sec-title q-feedback__sec-title--strengths'>
                                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                                                    <polyline points="20 6 9 17 4 12"/>
                                                </svg>
                                                Key Strengths
                                            </h4>
                                            <ul className='q-feedback__list'>
                                                {feedback.strengths.map((str, idx) => (
                                                    <li key={idx}>{str}</li>
                                                ))}
                                            </ul>
                                        </div>

                                        <div className='q-feedback__section'>
                                            <h4 className='q-feedback__sec-title q-feedback__sec-title--gaps'>
                                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                                                    <line x1="18" y1="6" x2="6" y2="18"/>
                                                    <line x1="6" y1="6" x2="18" y2="18"/>
                                                </svg>
                                                Keyword & Logical Gaps
                                            </h4>
                                            <ul className='q-feedback__list'>
                                                {feedback.improvements.map((imp, idx) => (
                                                    <li key={idx}>{imp}</li>
                                                ))}
                                            </ul>
                                        </div>

                                        <div className='q-feedback__section q-feedback__section--revision'>
                                            <div className='q-feedback__sec-header'>
                                                <h4 className='q-feedback__sec-title q-feedback__sec-title--revision'>
                                                    Suggested STAR Method Revision
                                                </h4>
                                                <button
                                                    type="button"
                                                    className='q-feedback__copy-btn'
                                                    onClick={handleCopyRevision}
                                                >
                                                    {copied ? 'Copied!' : 'Copy to Clipboard'}
                                                </button>
                                            </div>
                                            <p className='q-feedback__revision-text'>{feedback.suggestedRevision}</p>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    )
}

const RoadMapDay = ({ day }) => (
    <div className='roadmap-day'>
        <div className='roadmap-day__header'>
            <span className='roadmap-day__badge'>Day {day.day}</span>
            <h3 className='roadmap-day__focus'>{day.focus}</h3>
        </div>
        <ul className='roadmap-day__tasks'>
            {day.tasks.map((task, i) => (
                <li key={i}>
                    <span className='roadmap-day__bullet' />
                    {task}
                </li>
            ))}
        </ul>
    </div>
)

// ── Main Component ────────────────────────────────────────────────────────────
const Interview = () => {
    const navigate = useNavigate()
    const [ activeNav, setActiveNav ] = useState(() => {
        const queryNav = new URLSearchParams(window.location.search).get('nav')
        return ['technical', 'behavioral', 'roadmap', 'insights'].includes(queryNav) ? queryNav : 'technical'
    })
    const { report, loading, getResumePdf, pdfGenerating, getReportById } = useInterview()
    const { interviewId } = useParams()

    useEffect(() => {
        if (interviewId) getReportById(interviewId)
    }, [interviewId, getReportById])

    if (loading || !report) {
        return <LoadingScreen />
    }

    const scoreColor =
        report.matchScore >= 80 ? 'score--high' :
            report.matchScore >= 60 ? 'score--mid' : 'score--low'

    // Previously hardcoded to "Strong match for this role", which was shown
    // even under a 20% score.
    const scoreSummary =
        report.matchScore >= 80 ? 'Strong match for this role' :
            report.matchScore >= 60 ? 'Decent match — close the gaps below' :
                'Weak match — significant gaps to address'


    return (
        <div className='interview-page'>
            {/* Desktop Layout (hidden on mobile via CSS) */}
            <div className='interview-layout'>

                {/* ── Left Nav ── */}
                <nav className='interview-nav'>
                    <div className="nav-content">
                        <button
                            type="button"
                            className="interview-nav__item"
                            onClick={() => navigate('/dashboard')}
                            style={{ 
                                marginBottom: '1.25rem', 
                                borderBottom: '1px solid rgba(255, 255, 255, 0.05)', 
                                borderRadius: '0', 
                                paddingBottom: '1rem',
                                width: '100%',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.6rem',
                                background: 'none',
                                border: 'none',
                                color: '#7d8590',
                                cursor: 'pointer',
                                fontSize: '0.875rem'
                            }}
                        >
                            <span className='interview-nav__icon' style={{ display: 'flex', alignItems: 'center' }}>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                    <line x1="19" y1="12" x2="5" y2="12"></line>
                                    <polyline points="12 19 5 12 12 5"></polyline>
                                </svg>
                            </span>
                            Back to Planner
                        </button>
                        <p className='interview-nav__label'>Sections</p>
                        {NAV_ITEMS.map(item => (
                            <button
                                key={item.id}
                                className={`interview-nav__item ${activeNav === item.id ? 'interview-nav__item--active' : ''}`}
                                onClick={() => setActiveNav(item.id)}
                            >
                                <span className='interview-nav__icon'>{item.icon}</span>
                                {item.label}
                            </button>
                        ))}
                    </div>
                    <button
                        onClick={() => { getResumePdf(interviewId) }}
                        disabled={pdfGenerating}
                        className='button primary-button' >
                        <svg height={"0.8rem"} style={{ marginRight: "0.8rem" }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M10.6144 17.7956 11.492 15.7854C12.2731 13.9966 13.6789 12.5726 15.4325 11.7942L17.8482 10.7219C18.6162 10.381 18.6162 9.26368 17.8482 8.92277L15.5079 7.88394C13.7092 7.08552 12.2782 5.60881 11.5105 3.75894L10.6215 1.61673C10.2916.821765 9.19319.821767 8.8633 1.61673L7.97427 3.75892C7.20657 5.60881 5.77553 7.08552 3.97685 7.88394L1.63658 8.92277C.868537 9.26368.868536 10.381 1.63658 10.7219L4.0523 11.7942C5.80589 12.5726 7.21171 13.9966 7.99275 15.7854L8.8704 17.7956C9.20776 18.5682 10.277 18.5682 10.6144 17.7956ZM19.4014 22.6899 19.6482 22.1242C20.0882 21.1156 20.8807 20.3125 21.8695 19.8732L22.6299 19.5353C23.0412 19.3526 23.0412 18.7549 22.6299 18.5722L21.9121 18.2532C20.8978 17.8026 20.0911 16.9698 19.6586 15.9269L19.4052 15.3156C19.2285 14.8896 18.6395 14.8896 18.4628 15.3156L18.2094 15.9269C17.777 16.9698 16.9703 17.8026 15.956 18.2532L15.2381 18.5722C14.8269 18.7549 14.8269 19.3526 15.2381 19.5353L15.9985 19.8732C16.9874 20.3125 17.7798 21.1156 18.2198 22.1242L18.4667 22.6899C18.6473 23.104 19.2207 23.104 19.4014 22.6899Z"></path></svg>
                        Download Resume
                    </button>
                </nav>

                <div className='interview-divider' />

                {/* ── Center Content ── */}
                <main className='interview-content'>
                    {activeNav === 'technical' && (
                        <section>
                            <div className='content-header'>
                                <h2>Technical Questions</h2>
                                <span className='content-header__count'>{report.technicalQuestions.length} questions</span>
                            </div>
                            <div className='q-list'>
                                {report.technicalQuestions.map((q, i) => (
                                    <QuestionCard key={i} item={q} index={i} jobDescription={report.jobDescription} />
                                ))}
                            </div>
                        </section>
                    )}

                    {activeNav === 'behavioral' && (
                        <section>
                            <div className='content-header'>
                                <h2>Behavioral Questions</h2>
                                <span className='content-header__count'>{report.behavioralQuestions.length} questions</span>
                            </div>
                            <div className='q-list'>
                                {report.behavioralQuestions.map((q, i) => (
                                    <QuestionCard key={i} item={q} index={i} jobDescription={report.jobDescription} />
                                ))}
                            </div>
                        </section>
                    )}

                    {activeNav === 'roadmap' && (
                        <section>
                            <div className='content-header'>
                                <h2>Preparation Road Map</h2>
                                <span className='content-header__count'>{report.preparationPlan.length}-day plan</span>
                            </div>
                            <div className='roadmap-list'>
                                {report.preparationPlan.map((day) => (
                                    <RoadMapDay key={day.day} day={day} />
                                ))}
                            </div>
                        </section>
                    )}
                </main>

                <div className='interview-divider' />

                {/* ── Right Sidebar ── */}
                <aside className='interview-sidebar'>

                    {/* Match Score */}
                    <div className='match-score'>
                        <p className='match-score__label'>Match Score</p>
                        <div className={`match-score__ring ${scoreColor}`}>
                            <span className='match-score__value'>{report.matchScore}</span>
                            <span className='match-score__pct'>%</span>
                        </div>
                        <p className='match-score__sub'>{scoreSummary}</p>
                    </div>

                    <div className='sidebar-divider' />

                    {/* Skill Gaps */}
                    <div className='skill-gaps'>
                        <p className='skill-gaps__label'>Skill Gaps</p>
                        <div className='skill-gaps__list'>
                            {report.skillGaps.map((gap, i) => (
                                <span key={i} className={`skill-tag skill-tag--${gap.severity}`}>
                                    {gap.skill}
                                </span>
                            ))}
                        </div>
                    </div>

                </aside>
            </div>

            {/* Mobile Layout (hidden on desktop via CSS) */}
            <div className='interview-mobile-layout'>
                {/* Mobile Header Row */}
                <header className='mobile-interview-header'>
                    <button type="button" className='mobile-back-btn' onClick={() => navigate('/dashboard')}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                            <line x1="19" y1="12" x2="5" y2="12"></line>
                            <polyline points="12 19 5 12 12 5"></polyline>
                        </svg>
                        Back
                    </button>
                    <span className='mobile-header-title'>{report.title || 'Strategy Report'}</span>
                    <button 
                        type="button"
                        className='mobile-download-btn' 
                        onClick={() => getResumePdf(interviewId)}
                        disabled={pdfGenerating}
                    >
                        {pdfGenerating ? '...' : 'PDF'}
                    </button>
                </header>

                {/* Mobile Sticky Tab Segment Bar */}
                <nav className='mobile-interview-tabs'>
                    {MOBILE_NAV_ITEMS.map(item => (
                        <button
                            key={item.id}
                            type="button"
                            className={`mobile-tab-item ${activeNav === item.id ? 'active' : ''}`}
                            onClick={() => setActiveNav(item.id)}
                        >
                            <span className='tab-icon'>{item.icon}</span>
                            <span className='tab-label'>{item.label}</span>
                        </button>
                    ))}
                </nav>

                {/* Mobile Active Panel Content Pane */}
                <main className='mobile-interview-content'>
                    {activeNav === 'technical' && (
                        <section>
                            <div className='content-header'>
                                <h2>Technical Questions</h2>
                                <span className='content-header__count'>{report.technicalQuestions.length} questions</span>
                            </div>
                            <div className='q-list'>
                                {report.technicalQuestions.map((q, i) => (
                                    <QuestionCard key={i} item={q} index={i} jobDescription={report.jobDescription} />
                                ))}
                            </div>
                        </section>
                    )}

                    {activeNav === 'behavioral' && (
                        <section>
                            <div className='content-header'>
                                <h2>Behavioral Questions</h2>
                                <span className='content-header__count'>{report.behavioralQuestions.length} questions</span>
                            </div>
                            <div className='q-list'>
                                {report.behavioralQuestions.map((q, i) => (
                                    <QuestionCard key={i} item={q} index={i} jobDescription={report.jobDescription} />
                                ))}
                            </div>
                        </section>
                    )}

                    {activeNav === 'roadmap' && (
                        <section>
                            <div className='content-header'>
                                <h2>Preparation Road Map</h2>
                                <span className='content-header__count'>{report.preparationPlan.length}-day plan</span>
                            </div>
                            <div className='roadmap-list'>
                                {report.preparationPlan.map((day) => (
                                    <RoadMapDay key={day.day} day={day} />
                                ))}
                            </div>
                        </section>
                    )}

                    {activeNav === 'insights' && (
                        <section className='mobile-insights-tab-pane'>
                            {/* Match Score */}
                            <div className='mobile-match-score-card'>
                                <h3>Alignment Match Score</h3>
                                <div className={`match-score-ring-wrapper ${scoreColor}`}>
                                    <span className='score-num'>{report.matchScore}</span>
                                    <span className='score-pct'>%</span>
                                </div>
                                <p className='score-evaluation-text'>
                                    {report.matchScore >= 80 
                                        ? '✓ Profile matching ratio is outstanding for this position.' 
                                        : report.matchScore >= 60 
                                            ? '⚠ Good matching score. Address the key gaps below to pass ATS screening.' 
                                            : '✗ Low match score. Recommended to optimize resume fields to meet basic guidelines.'}
                                </p>
                            </div>

                            {/* Skill Gaps Card */}
                            <div className='mobile-skill-gaps-card'>
                                <h3>Detected Gaps in Profile</h3>
                                <div className='skill-gaps-grid-list'>
                                    {report.skillGaps.length > 0 ? (
                                        report.skillGaps.map((gap, i) => (
                                            <div key={i} className={`mobile-skill-gap-item mobile-skill-gap-item--${gap.severity}`}>
                                                <span className='skill-name'>{gap.skill}</span>
                                                <span className='severity-badge'>{gap.severity}</span>
                                            </div>
                                        ))
                                    ) : (
                                        <p className='no-gaps-found-msg'>✓ No profile skill gaps detected. ATS matching index is stable!</p>
                                    )}
                                </div>
                            </div>
                        </section>
                    )}
                </main>
            </div>

            <ResumePdfModal />
        </div>
    )
}

export default Interview