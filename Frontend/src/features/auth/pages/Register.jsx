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
      <main className="login-page">
        <section className="login-card" aria-label="Create account form">
          <div className="brand-panel">
            <span className="brand-mark" aria-hidden="true">
              IA
            </span>
            <div>
              <p className="brand-label">Interview AI</p>
              <h1>Creating account...</h1>
            </div>
          </div>
        </section>
      </main>
    )
  }

  return (
    <main className="login-page">
      <section className="login-card" aria-label="Create account form">
        <div className="brand-panel">
          <span className="brand-mark" aria-hidden="true">
            IA
          </span>
          <div>
            <p className="brand-label">Interview AI</p>
            <h1>Create your account</h1>
          </div>
        </div>

        <p className="card-subtitle">
          Start your interview preparation with a secure account.
        </p>

        <form onSubmit={handleSubmit}>
          <div className="input-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              placeholder="janedoe"
              autoComplete="username"
            />
          </div>

          <div className="input-group">
            <label htmlFor="email">Email address</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="you@example.com"
              autoComplete="email"
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
              placeholder="Create a password"
              autoComplete="new-password"
            />
          </div>

          <button type="submit" className="button primary-button">
            Create account
          </button>

          <div className="login-footer">
            <Link to="/login" className="secondary-link">
              Already have an account? Sign in
            </Link>
            <Link to="/login" className="secondary-link">
              Need help?
            </Link>
          </div>
        </form>
      </section>
    </main>
  )
}

export default Register
