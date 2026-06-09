# 🚀 Interview Copilot — Enterprise-Grade GenAI Job Preparation Platform

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Interview%20Copilot-blueviolet?style=flat-square&logo=vercel)](https://interview-copilot-ai-iota.vercel.app/)
[![Backend Status](https://img.shields.io/badge/Backend-Deployed%20on%20Render-blue?style=flat-square&logo=render)](https://render.com)
[![Vite](https://img.shields.io/badge/Frontend-Vite%20%2B%20React-646CFF?style=flat-square&logo=vite)](https://vitejs.dev)
[![Node](https://img.shields.io/badge/Runtime-Node.js%20v18%2B-339933?style=flat-square&logo=node.js)](https://nodejs.org)
[![MongoDB](https://img.shields.io/badge/Database-MongoDB%20Atlas-47A248?style=flat-square&logo=mongodb)](https://www.mongodb.com)

An enterprise-ready, full-stack web application designed to optimize technical job preparation. Candidates upload resumes, paste target job descriptions, analyze alignment using Generative AI, and receive customized study roadmaps alongside ATS-optimized resume PDFs.

Rather than acting as a simple LLM API wrapper, this platform is engineered with strict runtime validation schemas, isolated document compiler runtimes, and a stateless token invalidation backend.

---

## 🏛 System Architecture & Design Patterns

The platform implements a highly decoupled **4-Layer Architecture** across both sides of the network boundary to isolate execution contexts, enforce clean error boundaries, and manage state transitions deterministically.

```
                  ┌─────────────────────────────────────────┐
                  │              CLIENT LAYER               │
                  │        React.js (Vite) / SCSS           │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │              STATE LAYER                │
                  │   Context API / useAuth / useInterview  │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │         SERVICE LAYER (Axios)           │
                  │   Client-side API requests / Handlers   │
                  └────────────────────┬────────────────────┘
                                       │
=======================================│=======================================
                               NETWORK BOUNDARY (CORS Secured)
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │          CONTROLLERS & ROUTING          │
                  │        Express.js Router / JWT          │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │             BUSINESS LOGIC              │
                  │   AI Service (Gemini) / Puppeteer PDF   │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │               DATA LAYER                │
                  │       MongoDB Atlas / Mongoose          │
                  └─────────────────────────────────────────┘
```

---

## 🧱 Core Engineering Implementations

### 1. Deterministic GenAI Pipelines (Gemini + Zod Validation)
Standard LLMs suffer from formatting deviations and hallucinated fields. To guarantee backend stability:
- We enforce structured JSON responses directly from the **Gemini API** via native `responseSchema` constraints.
- Response payloads are parsed and validated at the API boundary using **Zod Schemas** before execution flow moves to the database layer. This ensures that any deviation in the AI schema triggers a graceful transaction rollback without corrupting application state.

### 2. Headless PDF Compilation Engine
Generating high-fidelity, ATS-friendly documents can cause severe CPU bottlenecks:
- The system processes resume PDFs through **Multer memory storage**, bypassing persistent disk I/O latency.
- An optimized **Puppeteer** pipeline instantiates a headless Chromium runtime to compile dynamic HTML templates into standardized A4-sized PDF binaries.
- To prevent memory leaks, browser instances are safely closed using a robust `finally` block orchestration pattern under heavy API load.

### 3. Stateful Rehydration & Route Security
- Global user session state is preserved in a secure Context wrapper.
- On client reload, a session rehydration protocol hits the `/api/auth/me` endpoint to dynamically reconstruct the state machine, preventing abrupt UI resets.
- Access to dashboard and reporting interfaces is guarded on the client by declarative router wraps (`ProtectedRoute`) and validated on the backend by express token checkers.

### 4. TTL-Based Stateless Token Blacklisting
To support secure logouts without introducing stateful session stores (e.g., Redis):
- On user logout, the active JWT is extracted and pushed to a MongoDB-backed `blacklist` collection.
- A **TTL (Time-To-Live) index** automatically purges expired tokens from the collection exactly matching the expiration timestamp of the token.
- Every authenticated request checks this database in $O(1)$ time complexity, ensuring absolute revocation capabilities with zero manual cleanup overhead.

---

## 🛠 Tech Stack & Dependencies

### Frontend
- **Framework:** React.js (v19) configured with Vite for high-speed module reloading.
- **Routing:** React Router DOM (v7) for nested layouts and transitions.
- **Styling:** Custom SCSS variables mapped to a dark-mode theme, implementing responsive CSS grids and glassmorphic dashboards.
- **Network Client:** Axios instance with custom interceptors for attaching authorization tokens.

### Backend Infrastructure
- **Runtime:** Node.js (v18+) with Express.js.
- **Database:** MongoDB Atlas with Mongoose schemas.
- **File Upload:** Multer middleware with strict size constraints.
- **Schema Validation:** Zod validation libraries.
- **Generation Tools:** Headless Puppeteer Core for static binary compilation.

---

## 📂 Repository Structure

```filepath
├── Backend/
│   ├── config/             # Database connectivity, CORS definitions & dotenv configs
│   ├── controllers/        # Request handlers (Auth controllers, Interview engines, PDF engines)
│   ├── middlewares/        # Security wrappers, JWT validators, and multer setups
│   ├── models/             # Strict Mongoose schemas (User, TokenBlacklist, InterviewReport)
│   ├── routes/             # RESTful API routing configuration mapping path structures
│   ├── services/           # GenAI prompt compilation & Puppeteer PDF generators
│   └── server.js           # Server initializer and listener
└── Frontend/
    ├── public/             # Static brand assets (custom SVG/PNG icons & favicon)
    ├── src/
    │   ├── components/     # High-fidelity reusable UI elements (Modals, Toast layers)
    │   ├── context/        # State Machines (Global Authentication, Interview Context)
    │   ├── features/       # Feature-driven modules (Interview dashboard, generate page, landing)
    │   ├── hooks/          # React hooks abstracting complex two-way bindings
    │   ├── services/       # Structured Axios API service interfaces
    │   └── styles/         # SASS stylesheets supporting dynamic themes
```

---

## 🔌 API Documentation

### Authentication Subsystem
*   `POST /api/auth/register` — Creates a new candidate profile.
*   `POST /api/auth/login` — Verifies credentials and sets secure JWT cookie.
*   `POST /api/auth/logout` — Blacklists the current JWT and clears client cookies.
*   `GET /api/auth/me` — Fetches current session details for active state rehydration.

### Interview Copilot Subsystem
*   `POST /api/interview/` — Compiles self-description, job descriptions, and resume files to generate a structured interview plan.
*   `GET /api/interview/` — Retrieves a list of all historical generation plans for the active user.
*   `GET /api/interview/report/:interviewId` — Fetches detailed question, answer, and roadmap structures for a specific generation.
*   `POST /api/interview/resume/pdf/:interviewReportId` — Triggers the server-side Puppeteer engine to compile and stream an ATS resume PDF.
*   `POST /api/interview/practice/evaluate` — Evaluates practice answers using Gemini with detailed criteria grading.

---

## ⚙️ Production Setup & Execution

### 1. Prerequisites
- Node.js (v18 or v20 LTS recommended)
- A running MongoDB instance (Local or Atlas)
- Google Gemini API key

### 2. Backend Environment Setup
Create a `.env` file in the `Backend` directory:
```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_signing_secret
GEMINI_API_KEY=your_gemini_api_key
FRONTEND_URL=http://localhost:5173
```

### 3. Local Development Start
To run the server and client concurrently in your local environment:

#### Launch Backend Service:
```bash
cd Backend
npm install
npm run dev
```

#### Launch Frontend Service:
```bash
cd Frontend
npm install
npm run dev
```
The client dashboard will start at `http://localhost:5173`.
