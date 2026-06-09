import { useContext, useEffect } from "react";
import { AuthContext } from "../auth.context.jsx";
import { login, register, logout, getMe } from '../services/auth.api';
import { useToast } from "../../interview/components/Toast.jsx";

const useAuth = () => {
    const context = useContext(AuthContext);
    const {user, setUser, loading, setLoading} = context;
    const { showToast } = useToast()

    const handleLogin = async ({email, password}) => {
        setLoading(true);
        try{
            if (!email || !password) {
                showToast("Please provide both email and password.", "warning");
                return false;
            }
            const data = await login({email, password});
            setUser(data.user);
            showToast(`Welcome back, ${data.user.username}!`, "success");
            return true;
        }
        catch(err){
            console.error("Login hook error:", err);
            const msg = err.response?.data?.message || "Incorrect email or password. Please try again.";
            showToast(msg, "error");
            return false;
        }
        finally{
            setLoading(false);
        }
    }

    const handleRegister = async ({username, email, password}) => {
        setLoading(true);
        try{
            if (!username || !email || !password) {
                showToast("All fields are required.", "warning");
                return false;
            }
            const data = await register({username, email, password});
            setUser(data.user);
            showToast("Account created successfully! Welcome to Interview Copilot.", "success");
            return true;
        }
        catch(err){
            console.error("Registration hook error:", err);
            const msg = err.response?.data?.message || "Registration failed. Please check your credentials.";
            showToast(msg, "error");
            return false;
        }
        finally{
            setLoading(false);
        }
    }

    const handleLogout = async () => {
        setLoading(true);
        try{
            await logout();
            setUser(null);
            showToast("Logged out successfully.", "info");
        }
         catch(err){
            console.error("Logout hook error:", err);
            showToast("Failed to logout gracefully.", "error");
        }
        setLoading(false);
    }

    useEffect(()=>{
        const fetchUser = async () => {
            try{
                const userData = await getMe();
                setUser(userData);
            } catch (error) {
                console.error('Error fetching user data:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchUser();
    }, []);

    return {user, loading, handleLogin, handleRegister, handleLogout}
}

export default useAuth;