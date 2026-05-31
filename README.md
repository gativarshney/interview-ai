# 🚀 Full-Stack GenAI Job Preparation Platform (Interview Copilot)

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Interview%20Copilot-blueviolet?style=flat-square&logo=vercel)](https://interview-copilot-ai-iota.vercel.app/)
[![Backend Status](https://img.shields.io/badge/Backend-Deployed%20on%20Render-blue?style=flat-square&logo=render)](https://render.com)

An enterprise-ready, full-stack web application designed to help candidates prepare for technical interviews. The platform allows users to upload their resumes, analyze targeted job descriptions to detect technical skill gaps, and generate customized interview questions alongside ATS-optimized resume PDFs using generative AI. 

Rather than acting as a simple API wrapper, the platform implements runtime schema validation, an isolated server-side document compilation pipeline, and stateless secure session management.

---

## 🏛 System Architecture & Design Patterns

The platform implements a highly decoupled, strict **4-Layer Architecture** across both sides of the network boundary to isolate execution contexts, maintain clean error boundaries, and manage state deterministically.


   [ CLIENT LAYER ]  <-->  [ SERVICE LAYER / API CLIENT ]

```

[ STATE / CONTEXT LAYER ] <-->  [ CUSTOM HOOKS (useAuth, useInterview) ]

======================== NETWORK BOUNDARY ========================

[ CONTROLLER LAYER ]    <-->   [ ROUTING / EXPRESS MIDDLEWARE ]
▲                               ▲
▼                               ▼
[ AI & PDF ENGINES ]   <-->    [ DATA LAYER (Mongoose Models) ]

```

### 🧱 Core Engineering Implementations

*   **Deterministic GenAI Pipelines (Zod + Gemini):** Integrates the **Gemini API** for resume parsing and skill extraction. To eliminate LLM JSON formatting inconsistencies or hallucinations, response formats are strictly validated at runtime using **Zod schemas** before persisting data to MongoDB.
*   **Server-Side Document Generation Pipeline:** Ingests unstructured candidate resumes via multipart/form-data processing using **Multer**. Following AI analysis, the backend triggers a server-side **Puppeteer** pipeline that spins up a headless browser instance to render a structured HTML/CSS template directly into an ATS-optimized PDF binary stream for the client.
*   **State Rehydration & Route Guarding:** Uses React Context and custom hooks (`useAuth`, `useInterview`) to handle global application states. Features an automated rehydration loop backing a backend `/getMe` routing context, preventing application state loss on manual browser refreshes while securing views via client-side `ProtectedRoute` wrappers.

---

## 🛠 Tech Stack & Core Subsystems

### Frontend
*   **Core Engine:** React.js (v18), Vite, React Router v6
*   **State Management:** React Context API (Global State Machines) + Custom Hook Abstractions
*   **Design System:** Tailwind CSS configured with a dark-mode layout, glassmorphic UI shells, premium responsive sidebars/navbars, custom validation toasts, and dynamic overlay animations.

### Backend Infrastructure
*   **Runtime Framework:** Node.js + Express.js Framework
*   **Database Engine:** MongoDB Atlas managed via Mongoose ODM
*   **File Streaming:** Multer (Memory Buffer Storage Ingestion)
*   **Automation Engine:** Puppeteer (Headless Chromium Server Orchestration)

---

## 🔒 Security Hardening & DevOps Operations

*   **Stateless Distributed Security:** Powered by secure JSON Web Tokens (JWT) passing through HTTP-Only cookies to protect client sessions against Cross-Site Scripting (XSS) risks.
*   **Token Blacklisting Protocol:** Handles secure session termination by tracking invalidated tokens in a high-speed MongoDB collection leveraging automatic **TTL (Time-To-Live) indexes** that expire concurrent with the JWT lifetime, ensuring zero database bloat.
*   **CORS Normalization:** Explicitly configures Cross-Origin Resource Sharing handling to resolve development and production domain origin mismatches (e.g., handling trailing slash discrepancies in deployment).
*   **Automated Continuous Deployment:** Configured via structural infrastructure blueprints for automated backend deployment on Render and automated single-page application hosting on Vercel.

---

## 📂 Repository Structure

```filepath
├── backend/
│   ├── config/             # Database connectivity & environmental setup
│   ├── controllers/        # Request handlers (Auth, Interview processing, PDF engine)
│   ├── middleware/         # Security checks, JWT verification, and route guards
│   ├── models/             # Mongoose schemas (User, Blacklist, InterviewReport)
│   ├── routes/             # Express API endpoints mapping controllers
│   └── services/           # External API integrations (Gemini, Puppeteer core)
└── frontend/
    ├── src/
    │   ├── components/     # UI components (Sidebar navigation, charts, forms)
    │   ├── context/        # Global state machines (AuthContext, InterviewContext)
    │   ├── hooks/          # Custom hooks handling state abstraction and two-way binding
    │   ├── services/       # Modular API client layers using Axios
    │   └── styles/         # Global design utilities and responsive layouts

```

---

## ⚙️ Local Setup Instructions

### 1. Prerequisites

* Node.js (v18 or higher)
* MongoDB instance (Local or Atlas cluster)

### 2. Environment Variables

Create a `.env` file in your `backend` directory:

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_signing_secret
GEMINI_API_KEY=your_gemini_api_key
FRONTEND_URL=http://localhost:5173

```

### 3. Execution Protocols

#### Start the Backend API Server:

```bash
cd backend
npm install
npm run dev

```

#### Start the Frontend Client:

```bash
cd frontend
npm install
npm run dev

```

The platform will automatically spin up on `http://localhost:5173`.
