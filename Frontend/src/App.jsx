import React from 'react'
import { RouterProvider } from "react-router-dom"
import { router } from "./app.routes.jsx"
import { AuthProvider } from './features/auth/auth.context.jsx'
import { InterviewProvider } from './features/interview/interview.context.jsx'
import { ToastProvider } from './features/interview/components/Toast.jsx'

function App() {
  return (
    <AuthProvider>
      <InterviewProvider>
        <ToastProvider>
          <RouterProvider router={router} />
        </ToastProvider>
      </InterviewProvider>
    </AuthProvider>
  )
}

export default App
