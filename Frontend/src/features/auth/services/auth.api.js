import axios from "axios"

const api = axios.create({
    baseURL: 'http://localhost:5000/api/auth',
    withCredentials: true
})

export async function register ({username, email, password}){
    try{
        const response = await api.post('/register', {
            username, email, password
        });
        return response.data;
    }
    catch(error){
        console.error('Registration failed:', error)
        throw error
    }
}

export async function login ({email, password}){
    try{
        const response = await api.post('/login', {
            email, password
        });
        return response.data;
    }
    catch(error){
        console.error('Login failed:', error)
        throw error
    }
}

export async function logout (){
    try{
        const response = await api.get('/logout');
        return response.data;
    }
    catch(error){
        console.error('Logout failed:', error)
        throw error
    }
}

export async function getMe (){
    try{
        const response = await api.get('/get-me');
        return response.data;
    }
    catch(error){
        console.error('Get current user failed:', error)
        throw error
    }
}