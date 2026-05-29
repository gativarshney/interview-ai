import axois from "axios"

axois.create({
    baseURL: 'http://localhost:3000/api/auth',
    withCredentials: true
})

export async function register ({username, email, password}){
    try{
        const response = await axois.post('/register', {
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
        const response = await axois.post('/login', {
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
        const response = await axois.get('/logout');
        return response.data;
    }
    catch(error){
        console.error('Logout failed:', error)
        throw error
    }
}

export async function getMe (){
    try{
        const response = await axois.get('/get-me');
        return response.data;
    }
    catch(error){
        console.error('Get current user failed:', error)
        throw error
    }
}