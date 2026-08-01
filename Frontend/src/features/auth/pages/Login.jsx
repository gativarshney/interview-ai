import React, { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import '../../auth/auth.scss'
import useAuth from '../hooks/useAuth'

const Login = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const { user, sessionLoading, submitting, handleLogin } = useAuth()

  const [ email, setEmail ] = useState("")
  const [ password, setPassword ] = useState("")

  const handleSubmit = async (e) => {
      e.preventDefault()
      const success = await handleLogin({email,password})
      if(success) {
        // Return them to whatever protected page sent them here.
        navigate(location.state?.from || '/dashboard', { replace: true })
      }
  }

  // Wait for the session check before deciding what to render, otherwise an
  // already-signed-in user sees the login form flash before the redirect.
  if (sessionLoading) {
    return (
      <div className="spinner-overlay">
        <div className="premium-spinner"></div>
        <span className="spinner-text">Loading...</span>
      </div>
    )
  }

  if (user) {
    return <Navigate to="/dashboard" replace />
  }

  return (
    <main className="login-page-container">
      {/* Cinematic background glows */}
      <div className='mesh-glow mesh-glow--magenta' />
      <div className='mesh-glow mesh-glow--teal' />

      <section className="login-glass-card" aria-label="Login form">
        <div className="auth-brand-header">
          <div className="auth-brand-badge">
            <span className="auth-brand-dot" />
            <span className="auth-brand-text">Interview<span className="auth-brand-text-accent"> Copilot</span></span>
          </div>
          <h1>Welcome back</h1>
          <p className="auth-card-subtitle">
            Sign in to pick up your interview plans where you left off.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form-flow">
          <div className="auth-input-group">
            <label htmlFor="email">Email Address</label>
            <input
              type="email"
              id="email"
              name="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="name@company.com"
              autoComplete="username"
              required
            />
          </div>

          <div className="auth-input-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              autoComplete="current-password"
              required
            />
          </div>

          <button type="submit" className="auth-submit-gradient-btn" disabled={submitting}>
            {submitting ? 'Signing in…' : 'Sign In'}
          </button>

          <div className="auth-links-footer">
            <Link to="/register" className="auth-footer-link">
              Don't have an account? <span className="highlight-text">Register</span>
            </Link>
            <span className="auth-links-separator">&bull;</span>
            <Link to="/" className="auth-footer-link">
              Back to home
            </Link>
          </div>
        </form>
      </section>
    </main>
  )
}

export default Login
