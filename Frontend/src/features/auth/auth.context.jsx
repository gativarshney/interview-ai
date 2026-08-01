import React, { createContext, useEffect, useState } from 'react';
import { getMe } from './services/auth.api';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    // True only while the initial "am I signed in?" check is in flight.
    const [sessionLoading, setSessionLoading] = useState(true);

    // Runs exactly once for the whole app. Previously every component calling
    // useAuth() fired its own /get-me, so one page load made several duplicate
    // requests.
    useEffect(() => {
        let cancelled = false;

        getMe()
            .then((data) => {
                // The API returns { message, user } — store the user, not the envelope.
                if (!cancelled) setUser(data?.user ?? null);
            })
            .catch(() => {
                // A 401 here just means "not signed in", which is the normal
                // state on public pages. Not an error worth surfacing.
                if (!cancelled) setUser(null);
            })
            .finally(() => {
                if (!cancelled) setSessionLoading(false);
            });

        return () => { cancelled = true };
    }, []);

    return (
        <AuthContext.Provider value={{ user, setUser, sessionLoading }}>
            {children}
        </AuthContext.Provider>
    )
}
