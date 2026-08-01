import React from 'react'
import { createRoot } from 'react-dom/client'
import { StrictMode } from 'react'
import App from './App.jsx'

// New design system first, then the legacy stylesheet, so pages that have not
// been migrated yet keep winning any conflict while the rebuild is in
// progress. style.scss is deleted once every page has moved over (UI-7).
import './index.css'
import './style.scss'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
