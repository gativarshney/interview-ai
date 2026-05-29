import React from 'react'
import { createBrowserRouter, Navigate } from 'react-router-dom'
import Home from './features/home/Home'
import Login from './features/auth/pages/Login'
import Register from './features/auth/pages/Register'

export const router = createBrowserRouter([
  {
    path: '/',
    element: <Home />,
  },
  {
    path: '/login',
    element: <Login />,
  },
  {
    path: '/register',
    element: <Register />,
  },
  {
    path: '*',
    element: <Navigate to='/' replace />,
  },
])