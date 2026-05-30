import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import useAuth from '../../auth/hooks/useAuth'
import '../styles/landing.scss'

const FAQ_ITEMS = [
    {
        q: "How does the AI analyze my resume and matching score?",
        a: "Our system parses the text of your uploaded resume PDF and runs dynamic cross-matching diagnostics against the job description using advanced Gemini LLM endpoints. It grades your profile against key skills, core concepts, and terminology, delivering a highly precise ATS scoring index."
    },
    {
        q: "What does the 7-day personalized road map contain?",
        a: "It breaks down your target alignment gaps into daily preparation tasks. Day 1-3 focus on severe technical and system design theory alignment, Day 4-5 detail targeted behavioral responses (STAR format), and Day 6-7 provide high-fidelity coding and structural simulation challenges tailored to the role."
    },
    {
        q: "Is my resume data safe and private?",
        a: "Absolutely. We secure your uploaded assets with enterprise-grade encryption. The parsed contents are only processed inside sandboxed context boundaries to compile your interview report and are never utilized to train public foundational AI models."
    },
    {
        q: "Can I generate resumes tailored for specific FAANG companies?",
        a: "Yes. Our AI generator extracts matching and missing keywords, cross-references target company hiring bars (such as Google's Googlyness or Amazon's Leadership Principles), and generates a fully ATS-optimized, high-fidelity PDF resume customized for that specific role."
    }
]

const Landing = () => {
    const { user, handleLogout } = useAuth()
    const navigate = useNavigate()
    const [openFaqIndex, setOpenFaqIndex] = useState(null)

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
                        <span className="logo-icon">IA</span>
                        <span className="logo-text">Interview AI</span>
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
                </div>
            </header>

            {/* 1. Hero Section */}
            <section className="hero-section">
                <div className="hero-container">
                    <span className="badge-promo">Next-Gen AI Interview Copilot</span>
                    <h1>Outprepare the Competition. <br /><span className="text-gradient">Clear the FAANG Bar.</span></h1>
                    <p className="hero-subtitle">
                        Audit your resume against real-world job descriptions, target high-severity skill gaps, and unlock a customized preparation blueprint engineered for Google, Stripe, and high-growth startups.
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
                            <div className="mockup-title">dashboard.interview-ai.app</div>
                        </div>
                        <div className="mockup-content">
                            <div className="mockup-sidebar">
                                <div className="mockup-logo">IA</div>
                                <div className="mockup-menu-item active">Dashboard</div>
                                <div className="mockup-menu-item">Strategies</div>
                                <div className="mockup-menu-item">Resume Intelligence</div>
                                <div className="mockup-menu-item">ATS Audit</div>
                            </div>
                            <div className="mockup-main">
                                <div className="mockup-widgets">
                                    <div className="widget-box">
                                        <p className="w-lbl">Interviews Cleared</p>
                                        <p className="w-val">12</p>
                                    </div>
                                    <div className="widget-box">
                                        <p className="w-lbl">Resume status</p>
                                        <p className="w-val" style={{ color: '#0c9c8a', fontSize: '0.85rem' }}>✓ Active.pdf</p>
                                    </div>
                                    <div className="widget-box">
                                        <p className="w-lbl">Latest ATS Score</p>
                                        <p className="w-val" style={{ color: '#ff2d78' }}>94%</p>
                                    </div>
                                </div>
                                <div className="mockup-chart-row">
                                    <div className="chart-card">
                                        <h4>Preparation Roadmap Progression</h4>
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
                    <h2>Unparalleled Intelligence. <br />Better Prep.</h2>
                    <p>Traditional mock interview tools drills you with generic, unaligned questions. Interview-AI synthesizes structured strategy blueprints customized to your unique profile and the target job description.</p>
                </div>
            </section>

            {/* 3. Features Grid */}
            <section id="features" className="section-padding features-section">
                <div className="section-header">
                    <h2>Platform Capabilities</h2>
                    <p>Every feature you need to dissect job expectations and stand out to top recruiters.</p>
                </div>
                <div className="features-grid">
                    
                    {/* Feature 1: AI Simulator */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--1">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>
                        </div>
                        <h3>AI Interview Simulator</h3>
                        <p>Simulates company-specific technical challenges matching actual Google, Amazon, and Microsoft hiring standards.</p>
                    </div>

                    {/* Feature 2: Resume Intelligence */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--2">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                        </div>
                        <h3>Resume Intelligence</h3>
                        <p>Extracts structure, keywords, and qualifications from your profile to check technical matching ratios instantly.</p>
                    </div>

                    {/* Feature 3: ATS Optimization */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--3">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
                        </div>
                        <h3>ATS Keyphrase Audit</h3>
                        <p>Checks your profile against applicant tracking parameters, providing actionable scoring diagnostics to pass resume filters.</p>
                    </div>

                    {/* Feature 4: Skill Gaps */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--4">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 2 22 22 22"></polygon><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                        </div>
                        <h3>Skill Gap Detection</h3>
                        <p>Identifies exact technologies or conceptual gaps missing from your resume that are explicitly demanded by the recruiter.</p>
                    </div>

                    {/* Feature 5: Personalized Roadmaps */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--1">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="3 11 22 2 13 21 11 13 3 11"></polygon></svg>
                        </div>
                        <h3>Dynamic Prep Blueprints</h3>
                        <p>Formulates a day-by-day structured checklist targeted at closing technical and behavioral gaps in under 7 days.</p>
                    </div>

                    {/* Feature 6: Dashboard Analytics */}
                    <div className="feature-card">
                        <div className="feature-icon feature-icon--2">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                        </div>
                        <h3>Comprehensive Dashboard</h3>
                        <p>A unified interface tracking all completed plans, resume readiness, matching statistics, and recommended quick triggers.</p>
                    </div>
                </div>
            </section>

            {/* 4. How It Works */}
            <section id="how-it-works" className="section-padding how-it-works-section">
                <div className="section-header">
                    <h2>How It Works</h2>
                    <p>Four streamlined steps from connecting your profile to clearing the final onboarding round.</p>
                </div>
                <div className="works-timeline">
                    <div className="timeline-node">
                        <div className="node-num">1</div>
                        <h4>Upload Profile &amp; Role</h4>
                        <p>Paste the target job description and drop in your resume PDF or self-description.</p>
                    </div>
                    <div className="timeline-node">
                        <div className="node-num">2</div>
                        <h4>AI Audits Gaps</h4>
                        <p>Our AI processes key technologies, structures, and identifies critical ATS keyword alignments.</p>
                    </div>
                    <div className="timeline-node">
                        <div className="node-num">3</div>
                        <h4>Synthesize Blueprint</h4>
                        <p>Get technical questions, STAR behavioral frameworks, and a day-by-day study roadmap.</p>
                    </div>
                    <div className="timeline-node">
                        <div className="node-num">4</div>
                        <h4>Practice &amp; Excel</h4>
                        <p>Resolve severities, optimize custom PDF resumes, and clear your recruiter screens with confidence.</p>
                    </div>
                </div>
            </section>

            {/* 5. Testimonials */}
            <section className="section-padding testimonials-section">
                <div className="section-header">
                    <h2>Success Stories</h2>
                    <p>Hear from software engineers who used our strategy blueprints to secure offers at leading tech companies.</p>
                </div>
                <div className="testimonials-grid">
                    <div className="t-card">
                        <p className="quote">"The skill gap detection alone changed my prep. It pointed out 3 keywords missing in my React profile that Google wanted. I added them, followed the 7-day roadmap, and aced the screen!"</p>
                        <div className="t-author">
                            <strong>Sarah Jenkins</strong>
                            <span>Software Engineer at Google</span>
                        </div>
                    </div>
                    <div className="t-card">
                        <p className="quote">"I was struggling to tailor my backend profile for different fintech companies. With Interview-AI, I generated tailored strategies for Stripe and Notion, achieving an immediate lift in response rates."</p>
                        <div className="t-author">
                            <strong>Michael Chang</strong>
                            <span>Backend Engineer at Stripe</span>
                        </div>
                    </div>
                    <div className="t-card">
                        <p className="quote">"Clear, intuitive, and extremely visual. The daily checklists saved me from information overload. I cleared my Meta technical loops by following the behavioral STAR prompts."</p>
                        <div className="t-author">
                            <strong>Elena Rostova</strong>
                            <span>Frontend Architect at Meta</span>
                        </div>
                    </div>
                </div>
            </section>

            {/* 6. FAQ Section */}
            <section id="faq" className="section-padding faq-section">
                <div className="section-header">
                    <h2>Frequently Asked Questions</h2>
                    <p>Find quick answers to common queries about our AI strategizer platform.</p>
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
                        Stop guessing what recruiters want. Synthesize your personalized preparation roadmap, close technical skill gaps, and execute a winning strategy built for the world's most elite engineering teams.
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

                    {/* Trust Signals */}
                    <div className="cta-trust-signals">
                        <p className="trust-heading">JOIN SOFTWARE ENGINEERS PLACED AT</p>
                        <div className="trust-logos-row">
                            <span className="brand-badge">Google</span>
                            <span className="brand-badge">Stripe</span>
                            <span className="brand-badge">Meta</span>
                            <span className="brand-badge">Netflix</span>
                        </div>
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="landing-footer">
                <div className="footer-container">
                    <div className="footer-brand">
                        <span className="logo-icon">IA</span>
                        <p>&copy; {new Date().getFullYear()} Interview AI. All rights reserved. Built for engineering excellence.</p>
                    </div>
                    <div className="footer-links">
                        <a href="#">Privacy Policy</a>
                        <a href="#">Terms of Service</a>
                        <a href="#">Security</a>
                        <a href="#">Contact Support</a>
                    </div>
                </div>
            </footer>
        </div>
    )
}

export default Landing
