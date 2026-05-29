import { useContext, useEffect } from "react";
import { AuthContext } from "../auth.context.jsx";
import { login, register, logout, getMe } from '../services/auth.api';

const useAuth = () => {
    const context = useContext(AuthContext);
    const {user, setUser, loading, setLoading} = context;

    const handleLogin = async ({email, password}) => {
        setLoading(true);
        try{
            const data = await login({email, password});
            setUser(data.user);
            return true;
        }
        catch(err){
            console.log(err);
            return false;
        }
        finally{
            setLoading(false);
        }
    }

    const handleRegister = async ({username, email, password}) => {
        setLoading(true);
        try{
            const data = await register({username, email, password});
            setUser(data.user);
            return true;
        }
        catch(err){
            console.log(err);
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
        }
         catch(err){
            console.log(err);
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