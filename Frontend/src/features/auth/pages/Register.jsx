import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import '../../auth/auth.scss'
import useAuth from '../hooks/useAuth'

const Register = () => {
  const navigate = useNavigate()
  const { loading, handleRegister } = useAuth()
  const [formData, setFormData] = useState({ username: '', email: '', password: '' })

  const handleChange = (event) => {
    const { name, value } = event.target
    setFormData((current) => ({ ...current, [name]: value }))
  }

  const handleSubmit = async (event) => {
    event.preventDefault()
    const success = await handleRegister(formData)
    if (success) {
      navigate('/')
    }
  }

  if (loading) {
    return (
      <div className="spinner-overlay">
        <div className="premium-spinner"></div>
        <span className="spinner-text">Creating your InterviewOS account...</span>
      </div>
    )
  }

  return (
    <main className="login-page-container">
      {/* Cinematic background glows */}
      <div className='mesh-glow mesh-glow--magenta' />
      <div className='mesh-glow mesh-glow--teal' />

      <section className="login-glass-card" aria-label="Create account form">
        <div className="auth-brand-header">
          <div className="auth-brand-badge">
            <span className="auth-brand-dot" />
            <span className="auth-brand-text">Interview<span className="auth-brand-text-accent">OS</span></span>
          </div>
          <h1>Create account</h1>
          <p className="auth-card-subtitle">
            Start your personalized MAANG preparation roadmap with InterviewOS.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form-flow">
          <div className="auth-input-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              placeholder="e.g. janesmith"
              autoComplete="username"
              required
            />
          </div>

          <div className="auth-input-group">
            <label htmlFor="email">Email Address</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="name@company.com"
              autoComplete="email"
              required
            />
          </div>

          <div className="auth-input-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="••••••••••••"
              autoComplete="new-password"
              required
            />
          </div>

          <button type="submit" className="auth-submit-gradient-btn">
            Create Account
          </button>

          <div className="auth-links-footer">
            <Link to="/login" className="auth-footer-link">
              Already have an account? <span className="highlight-text">Sign In</span>
            </Link>
            <span className="auth-links-separator">&bull;</span>
            <a href="#" className="auth-footer-link">
              Need help?
            </a>
          </div>
        </form>
      </section>
    </main>
  )
}

export default Register
