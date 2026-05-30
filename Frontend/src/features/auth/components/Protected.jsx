import useAuth from "../hooks/useAuth"
import React from "react"
import { Navigate } from "react-router-dom"

const Protected = ({ children }) => {
    const { user, loading } = useAuth()

    if(loading){
        return (
            <div className="spinner-overlay">
                <div className="premium-spinner"></div>
                <span className="spinner-text">Verifying Session...</span>
            </div>
        )
    }

    if(!user){
        return <Navigate to="/login" replace />
    }

    return children
}

export default Protected