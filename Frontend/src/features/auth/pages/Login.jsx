import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import '../../../style/auth.scss'
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
          navigate('/')
        }
    }

  if(loading){
    return (
      <main className="login-page">
        <section className="login-card" aria-label="Login form">
          <div className="brand-panel">
            <span className="brand-mark" aria-hidden="true">
              IA
            </span>
            <div>
              <p className="brand-label">Interview AI</p>
              <h1>Loading...</h1>
            </div>
          </div>
          </section>
      </main>
    )
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
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              name="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
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
              value={password}
              onChange={(e) => setPassword(e.target.value)}
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
