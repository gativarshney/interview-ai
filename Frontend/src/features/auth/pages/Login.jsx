import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import '../../auth/auth.scss'
import useAuth from '../hooks/useAuth'

const Login = () => {
  const navigate = useNavigate()
  const { loading, handleLogin } = useAuth()

  const [ email, setEmail ] = useState("")
  const [ password, setPassword ] = useState("")

  const handleSubmit = async (e) => {
      e.preventDefault()
      const success = await handleLogin({email,password})
      if(success) {
        navigate('/dashboard')
      }
  }

  if(loading){
    return (
      <div className="spinner-overlay">
        <div className="premium-spinner"></div>
        <span className="spinner-text">Signing in to Interview Copilot...</span>
      </div>
    )
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
            Sign in to access your custom strategies and simulation blueprints.
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

          <button type="submit" className="auth-submit-gradient-btn">
            Sign In
          </button>

          <div className="auth-links-footer">
            <Link to="/register" className="auth-footer-link">
              Don't have an account? <span className="highlight-text">Register</span>
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

export default Login
