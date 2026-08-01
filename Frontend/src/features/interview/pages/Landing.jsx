import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import useAuth from '../../auth/hooks/useAuth'
import '../styles/landing.scss'

const FAQ_ITEMS = [
    {
        q: "How is the match score calculated?",
        a: "Your resume PDF is parsed to text and sent, along with the job description, to Google's Gemini model. It compares the skills, technologies and experience in your profile against what the role asks for and returns a 0–100 score. It is a model's judgement of fit, not a guarantee of how any specific company's screening software will rate you."
    },
    {
        q: "What is in the preparation plan?",
        a: "A day-by-day breakdown generated from the gaps found between your profile and the target role — each day has a focus area and a short list of concrete tasks. Alongside it you get technical and behavioural questions, each with the reason an interviewer would ask it and notes on how to answer."
    },
    {
        q: "What happens to my resume data?",
        a: "Be aware of what this involves: your resume is parsed to text, stored in our database, and sent to Google's Gemini API to generate your report. It is not sold or shared with anyone else, and Google states that data sent through the paid Gemini API is not used to train their models. This is a personal project, not an audited service — please do not upload anything you would not be comfortable sharing."
    },
    {
        q: "Can I generate a resume tailored to a specific role?",
        a: "Yes. It rewrites and reorders your existing experience to emphasise what the job description asks for, then renders it to a clean single-column PDF that parses correctly in applicant tracking systems. It will not invent employers, dates or achievements that are not already in your resume — if something is missing, it is left out rather than made up."
    }
]

const Landing = () => {
    const { user, handleLogout } = useAuth()
    const navigate = useNavigate()
    const [openFaqIndex, setOpenFaqIndex] = useState(null)
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

    const toggleFaq = (index) => {
        setOpenFaqIndex(openFaqIndex === index ? null : index)
    }

    const handleCTA = () => {
        if (user) {
            navigate('/dashboard')
        } else {
            navigate('/register')
        }
    }

    const scrollSection = (id) => {
        const el = document.getElementById(id)
        if (el) {
            el.scrollIntoView({ behavior: 'smooth' })
        }
    }

    return (
        <div className="landing-page">
            
            {/* Ambient Radial Lights */}
            <div className="radial-glow radial-glow--1" />
            <div className="radial-glow radial-glow--2" />
            
            {/* Navbar */}
            <header className="landing-navbar">
                <div className="nav-container">
                    <div className="brand-logo" onClick={() => navigate('/')}>
                        <div className="brand-glow-dot" />
                        <span className="brand-text-main">Interview<span className="brand-text-accent"> Copilot</span></span>
                    </div>
                    <nav className="nav-links">
                        <button onClick={() => scrollSection('overview')}>Overview</button>
                        <button onClick={() => scrollSection('features')}>Features</button>
                        <button onClick={() => scrollSection('how-it-works')}>How it Works</button>
                        <button onClick={() => scrollSection('faq')}>FAQ</button>
                    </nav>
                    <div className="nav-ctas">
                        {user ? (
                            <>
                                <button className="btn-secondary" onClick={() => navigate('/dashboard')}>
                                    Dashboard
                                </button>
                                <button className="btn-logout" onClick={handleLogout}>
                                    Logout
                                </button>
                            </>
                        ) : (
                            <>
                                <button className="btn-text" onClick={() => navigate('/login')}>
                                    Sign In
                                </button>
                                <button className="btn-primary" onClick={() => navigate('/register')}>
                                    Get Started
                                </button>
                            </>
                        )}
                    </div>
                    
                    {/* Hamburger Button for Mobile View */}
                    <button 
                        className={`hamburger-btn ${mobileMenuOpen ? 'active' : ''}`} 
                        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                        aria-label="Toggle navigation menu"
                    >
                        <span className="hamburger-line"></span>
                        <span className="hamburger-line"></span>
                        <span className="hamburger-line"></span>
                    </button>
                </div>

                {/* Mobile Drawer Overlay */}
                <div className={`mobile-nav-drawer ${mobileMenuOpen ? 'open' : ''}`}>
                    <nav className="mobile-nav-links">
                        <button onClick={() => { scrollSection('overview'); setMobileMenuOpen(false); }}>Overview</button>
                        <button onClick={() => { scrollSection('features'); setMobileMenuOpen(false); }}>Features</button>
                        <button onClick={() => { scrollSection('how-it-works'); setMobileMenuOpen(false); }}>How it Works</button>
                        <button onClick={() => { scrollSection('faq'); setMobileMenuOpen(false); }}>FAQ</button>
                    </nav>
                    <div className="mobile-nav-ctas">
                        {user ? (
                            <>
                                <button className="btn-secondary" onClick={() => { navigate('/dashboard'); setMobileMenuOpen(false); }}>
                                    Dashboard
                                </button>
                                <button className="btn-logout" onClick={() => { handleLogout(); setMobileMenuOpen(false); }}>
                                    Logout
                                </button>
                            </>
                        ) : (
                            <>
                                <button className="btn-text" onClick={() => { navigate('/login'); setMobileMenuOpen(false); }}>
                                    Sign In
                                </button>
                                <button className="btn-primary" onClick={() => { navigate('/register'); setMobileMenuOpen(false); }}>
                                    Get Started
                                </button>
                            </>
                        )}
                    </div>
                </div>
            </header>

            {/* 1. Hero Section */}
            <section className="hero-section">
                <div className="hero-container">
                    <span className="badge-promo">Built for technical interviews</span>
                    <h1>Stop prepping in the dark. <br /><span className="text-gradient">Prep for the actual job.</span></h1>
                    <p className="hero-subtitle">
                        Paste the job description, upload your resume, and get back the questions you are likely to face, the gaps in your profile that matter, and a day-by-day plan to close them.
                    </p>
                    <div className="hero-ctas">
                        <button className="btn-primary btn-large" onClick={handleCTA}>
                            {user ? 'Go to Dashboard' : 'Get Started Free'}
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                        </button>
                        <button className="btn-secondary btn-large" onClick={() => scrollSection('overview')}>
                            Explore Capabilities
                        </button>
                    </div>

                    {/* Interactive Glassmorphic Dashboard Preview Mockup */}
                    <div className="hero-mockup-wrapper">
                        <div className="mockup-header">
                            <span className="mockup-dot red"></span>
                            <span className="mockup-dot yellow"></span>
                            <span className="mockup-dot green"></span>
                            <div className="mockup-title">dashboard.interviewcopilot.app</div>
                        </div>
                        <div className="mockup-content">
                            <div className="mockup-sidebar">
                                <div className="mockup-logo">IC</div>
                                <div className="mockup-menu-item active">My Plans</div>
                                <div className="mockup-menu-item">Questions</div>
                                <div className="mockup-menu-item">Prep Roadmap</div>
                                <div className="mockup-menu-item">Tailored Resume</div>
                            </div>
                            <div className="mockup-main">
                                <div className="mockup-widgets">
                                    <div className="widget-box">
                                        <p className="w-lbl">Plans Generated</p>
                                        <p className="w-val">3</p>
                                    </div>
                                    <div className="widget-box">
                                        <p className="w-lbl">Resume</p>
                                        <p className="w-val" style={{ color: '#0c9c8a', fontSize: '0.85rem' }}>resume.pdf</p>
                                    </div>
                                    <div className="widget-box">
                                        <p className="w-lbl">Match Score</p>
                                        <p className="w-val" style={{ color: '#ff2d78' }}>72%</p>
                                    </div>
                                </div>
                                <div className="mockup-chart-row">
                                    <div className="chart-card">
                                        <h4>Preparation Roadmap</h4>
                                        <div className="roadmap-bar-row">
                                            <span>Day 1: System Design</span><div className="bar"><div className="fill" style={{ width: '100%' }}></div></div>
                                        </div>
                                        <div className="roadmap-bar-row">
                                            <span>Day 2: Core JavaScript</span><div className="bar"><div className="fill" style={{ width: '80%' }}></div></div>
                                        </div>
                                        <div className="roadmap-bar-row">
                                            <span>Day 3: Practice Gaps</span><div className="bar"><div className="fill" style={{ width: '40%' }}></div></div>
                                        </div>
                                    </div>
                                    <div className="chart-card chart-card--small">
                                        <h4>Skill Gap Severity</h4>
                                        <span className="s-chip s-chip--high">React Server Components</span>
                                        <span className="s-chip s-chip--med">System Architecture</span>
                                        <span className="s-chip s-chip--low">Kubernetes</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* 2. Product Overview */}
            <section id="overview" className="section-padding overview-section">
                <div className="section-header">
                    <h2>The gap between prepared <br />and hired is smaller than you think.</h2>
                    <p>Most candidates fail not because they lack skill — but because they prep without direction. Interview Copilot closes that gap with a strategy built around your actual resume and the exact role you're targeting.</p>
                </div>
                <div className="overview-differentiators">
                    <div className="diff-card">
                        <span className="diff-icon">⚡</span>
                        <h4>Role-specific, not generic</h4>
                        <p>Every question, gap, and roadmap is generated from your resume against the actual job description — not a one-size-fits-all template.</p>
                    </div>
                    <div className="diff-card">
                        <span className="diff-icon">🎯</span>
                        <h4>Know exactly where you fall short</h4>
                        <p>Skill gap detection flags the precise technologies and concepts recruiters are screening for that your profile is missing.</p>
                    </div>
                    <div className="diff-card">
                        <span className="diff-icon">🗓️</span>
                        <h4>A 7-day plan, not just advice</h4>
                        <p>You get a day-by-day structured prep blueprint — not a list of tips. Actionable tasks from Day 1 to interview day.</p>
                    </div>
                </div>
            </section>

            {/* 3. Features Grid */}
            <section id="features" className="section-padding features-section">
                <div className="section-header">
                    <h2>What It Does</h2>
                    <p>Five things, built around one input: your resume and the job you are applying for.</p>
                </div>
                <div className="features-grid">
                    
                    {/* Feature 1: AI Simulator */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--1">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>
                        </div>
                        <h3>Role-Specific Questions</h3>
                        <p>Technical and behavioural questions generated from the job description you paste, each with the interviewer's intent and notes on how to answer.</p>
                    </div>

                    {/* Feature 2: Resume Intelligence */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--2">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                        </div>
                        <h3>Practice Arena</h3>
                        <p>Write your own answer to any question and get it graded against the STAR method, with specific gaps and a suggested rewrite.</p>
                    </div>

                    {/* Feature 3: ATS Optimization */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--3">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
                        </div>
                        <h3>Match Score</h3>
                        <p>A 0–100 read on how closely your profile lines up with the role, so you know where you stand before you apply.</p>
                    </div>

                    {/* Feature 4: Skill Gaps */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--4">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 2 22 22 22"></polygon><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                        </div>
                        <h3>Skill Gap Detection</h3>
                        <p>The specific technologies and concepts the job asks for that your resume does not mention, ranked low / medium / high.</p>
                    </div>

                    {/* Feature 5: Personalized Roadmaps */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--1">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="3 11 22 2 13 21 11 13 3 11"></polygon></svg>
                        </div>
                        <h3>Day-by-Day Prep Plan</h3>
                        <p>A dated checklist built around your actual gaps — a focus area and concrete tasks for each day, not a list of tips.</p>
                    </div>

                    {/* Feature 6: Dashboard Analytics */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--2">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                        </div>
                        <h3>Tailored Resume PDF</h3>
                        <p>Your real experience rewritten to emphasise what the role asks for, rendered to a clean single-column PDF that parses in ATS software.</p>
                    </div>
                </div>
            </section>

            {/* 4. How It Works */}
            <section id="how-it-works" className="section-padding how-it-works-section">
                <div className="section-header">
                    <h2>How It Works</h2>
                    <p>Four steps, about thirty seconds.</p>
                </div>
                <div className="works-timeline">
                    <div className="timeline-node">
                        <div className="node-num">1</div>
                        <h4>Upload Profile &amp; Role</h4>
                        <p>Paste the target job description and drop in your resume PDF or self-description.</p>
                    </div>
                    <div className="timeline-node">
                        <div className="node-num">2</div>
                        <h4>It Finds the Gaps</h4>
                        <p>Your experience is compared against what the role actually asks for, and the differences are ranked by how much they matter.</p>
                    </div>
                    <div className="timeline-node">
                        <div className="node-num">3</div>
                        <h4>You Get a Plan</h4>
                        <p>Technical and behavioural questions with model answers, plus a day-by-day checklist built around your gaps.</p>
                    </div>
                    <div className="timeline-node">
                        <div className="node-num">4</div>
                        <h4>Practice and Apply</h4>
                        <p>Rehearse your answers and get them graded, then download a version of your resume tailored to the role.</p>
                    </div>
                </div>
            </section>

            {/* 5. FAQ Section */}
            <section id="faq" className="section-padding faq-section">
                <div className="section-header">
                    <h2>Frequently Asked Questions</h2>
                    <p>How it works under the hood, and what happens to your data.</p>
                </div>
                <div className="faq-accordion">
                    {FAQ_ITEMS.map((item, idx) => (
                        <div 
                            key={idx} 
                            className={`faq-item ${openFaqIndex === idx ? 'open' : ''}`}
                            onClick={() => toggleFaq(idx)}
                        >
                            <div className="faq-question">
                                <h3>{item.q}</h3>
                                <span className="faq-toggle">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
                                </span>
                            </div>
                            <div className="faq-answer">
                                <p>{item.a}</p>
                            </div>
                        </div>
                    ))}
                </div>
            </section>

            {/* 7. Final Call to Action */}
            <section className="section-padding cta-banner-section">
                <div className="cta-banner-card">
                    <div className="cta-glow-element" />
                    <h2>Clear the Bar. <br /><span className="text-gradient">Land Your Dream Job Today.</span></h2>
                    <p>
                        Stop guessing what recruiters want. Synthesize your personalized preparation roadmap, close technical skill gaps, and execute a winning strategy built around the exact role you're targeting.
                    </p>
                    <div className="cta-actions-row">
                        <button className="btn-primary btn-large btn-pulsate" onClick={handleCTA}>
                            {user ? 'Go to Dashboard' : 'Get Started Free Now'}
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                        </button>
                        <button className="btn-secondary btn-large" onClick={() => scrollSection('overview')}>
                            Browse Capabilities
                        </button>
                    </div>

                </div>
            </section>

            {/* Footer */}
            <footer className="landing-footer">
                <div className="footer-container">
                    <div className="footer-brand">
                        <div className="brand-logo">
                            <div className="brand-glow-dot" />
                            <span className="brand-text-main">Interview<span className="brand-text-accent"> Copilot</span></span>
                        </div>
                        <p>&copy; {new Date().getFullYear()} Interview Copilot. All rights reserved.</p>
                    </div>
                    <div className="footer-links">
                        <a href="https://github.com/gativarshney/interview-ai" target="_blank" rel="noopener noreferrer">Source on GitHub</a>
                        <button type="button" onClick={() => scrollSection('faq')}>How it handles your data</button>
                    </div>
                </div>
            </footer>
        </div>
    )
}

export default Landing
