import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import '../../../style/auth.scss'

const Login = () => {
  const navigate = useNavigate()
  const [formData, setFormData] = useState({ userIdentifier: '', password: '' })

  const handleChange = (event) => {
    const { name, value } = event.target
    setFormData((current) => ({ ...current, [name]: value }))
  }

  const handleSubmit = (event) => {
    event.preventDefault()
    console.log('Login submit', formData)
    navigate('/')
  }

  return (
    <main className="login-page">
      <section className="login-card" aria-label="Login form">
        <div className="brand-panel">
          <span className="brand-mark" aria-hidden="true">
            IA
          </span>
          <div>
            <p className="brand-label">Interview AI</p>
            <h1>Welcome back</h1>
          </div>
        </div>

        <p className="card-subtitle">
          Sign in to access your interview insights and company reviews.
        </p>

        <form onSubmit={handleSubmit}>
          <div className="input-group">
            <label htmlFor="userIdentifier">Email or username</label>
            <input
              type="text"
              id="userIdentifier"
              name="userIdentifier"
              value={formData.userIdentifier}
              onChange={handleChange}
              placeholder="you@example.com"
              autoComplete="username"
            />
          </div>

          <div className="input-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="Enter your password"
              autoComplete="current-password"
            />
          </div>

          <button type="submit" className="button primary-button">
            Login
          </button>

          <div className="login-footer">
            <Link to="/register" className="secondary-link">
              Don't have an account? Register
            </Link>
            <Link to="/register" className="secondary-link">
              Need help?
            </Link>
          </div>
        </form>
      </section>
    </main>
  )
}

export default Login
