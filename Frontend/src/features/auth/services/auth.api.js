import axios from "axios"

const api = axios.create({
    baseURL: `${import.meta.env.VITE_API_URL || 'http://localhost:5000'}/api/auth`,
    withCredentials: true
})

export async function register({ username, email, password }) {
    const response = await api.post('/register', { username, email, password })
    return response.data
}

export async function login({ email, password }) {
    const response = await api.post('/login', { email, password })
    return response.data
}

export async function logout() {
    const response = await api.get('/logout')
    return response.data
}

export async function getMe() {
    // Callers decide what a failure means. A 401 here is the expected result for
    // a signed-out visitor, so this deliberately does not log an error.
    const response = await api.get('/get-me')
    return response.data
}
