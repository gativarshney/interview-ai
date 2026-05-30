import React from 'react'
import { createBrowserRouter, Navigate } from 'react-router-dom'
import Login from './features/auth/pages/Login'
import Register from './features/auth/pages/Register'
import Protected from './features/auth/components/Protected'
import Landing from './features/interview/pages/Landing'
import Dashboard from './features/interview/pages/Dashboard'
import Home from './features/interview/pages/Home'
import Interview from './features/interview/pages/Interview'

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <Login />,
  },
  {
    path: '/register',
    element: <Register />,
  },
  {
    path: '/',
    element: <Landing />
  },
  {
    path: '/dashboard',
    element: <Protected><Dashboard /></Protected>
  },
  {
    path: '/generate',
    element: <Protected><Home /></Protected>
  },
  {
    path: '/interview/:interviewId',
    element: <Protected><Interview /></Protected>
  },
  {
    path: '*',
    element: <Navigate to='/' replace />,
  },
])