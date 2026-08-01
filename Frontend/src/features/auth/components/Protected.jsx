import useAuth from "../hooks/useAuth"
import React from "react"
import { Navigate, useLocation } from "react-router-dom"

const Protected = ({ children }) => {
    const { user, sessionLoading } = useAuth()
    const location = useLocation()

    if (sessionLoading) {
        return (
            <div className="spinner-overlay">
                <div className="premium-spinner"></div>
                <span className="spinner-text">Verifying Session...</span>
            </div>
        )
    }

    if (!user) {
        // Remember where they were headed so login can return them there.
        return <Navigate to="/login" replace state={{ from: location.pathname }} />
    }

    return children
}

export default Protected
