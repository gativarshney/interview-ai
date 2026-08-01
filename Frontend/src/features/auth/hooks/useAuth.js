import { useCallback, useContext, useState } from "react";
import { AuthContext } from "../auth.context.jsx";
import { login, register, logout } from '../services/auth.api';
import { useToast } from "../../interview/components/Toast.jsx";

const useAuth = () => {
    const context = useContext(AuthContext);

    if (!context) {
        throw new Error("useAuth must be used within an AuthProvider");
    }

    const { user, setUser, sessionLoading } = context;
    const { showToast } = useToast()

    // Local to the component doing the submitting, so an in-flight login cannot
    // put the whole app back into its "verifying session" state.
    const [submitting, setSubmitting] = useState(false);

    const handleLogin = useCallback(async ({ email, password }) => {
        if (!email || !password) {
            showToast("Please provide both email and password.", "warning");
            return false;
        }

        setSubmitting(true);
        try {
            const data = await login({ email, password });
            setUser(data.user);
            showToast(`Welcome back, ${data.user.username}!`, "success");
            return true;
        } catch (err) {
            const msg = err.response?.data?.message || "Incorrect email or password. Please try again.";
            showToast(msg, "error");
            return false;
        } finally {
            setSubmitting(false);
        }
    }, [setUser, showToast]);

    const handleRegister = useCallback(async ({ username, email, password }) => {
        if (!username || !email || !password) {
            showToast("All fields are required.", "warning");
            return false;
        }

        setSubmitting(true);
        try {
            const data = await register({ username, email, password });
            setUser(data.user);
            showToast("Account created successfully! Welcome to Interview Copilot.", "success");
            return true;
        } catch (err) {
            const msg = err.response?.data?.message || "Registration failed. Please check your details.";
            showToast(msg, "error");
            return false;
        } finally {
            setSubmitting(false);
        }
    }, [setUser, showToast]);

    const handleLogout = useCallback(async () => {
        try {
            await logout();
        } catch {
            // Best effort server-side; either way the local session ends.
        } finally {
            setUser(null);
            showToast("Logged out successfully.", "info");
        }
    }, [setUser, showToast]);

    return { user, sessionLoading, submitting, handleLogin, handleRegister, handleLogout }
}

export default useAuth;
