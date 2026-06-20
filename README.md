# Interview Copilot

AI-powered interview preparation platform built with React, Express, MongoDB, and Google Gemini.

[![Live Demo](https://img.shields.io/badge/demo-live-success?style=flat-square)](https://interview-copilot-ai-iota.vercel.app/)
[![Node](https://img.shields.io/badge/node-%3E%3D18-339933?style=flat-square&logo=node.js)](https://nodejs.org)
[![React](https://img.shields.io/badge/react-19-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![MongoDB](https://img.shields.io/badge/database-MongoDB-47A248?style=flat-square&logo=mongodb)](https://www.mongodb.com)

## Overview

Interview Copilot takes a candidate's resume (or a free-text self-description) and a target job description, then uses Google Gemini to generate a structured interview preparation report: a match score, technical and behavioral questions with model answers, identified skill gaps, and a day-by-day study plan. Users can practice answering the generated questions and receive AI-graded feedback, and can generate an ATS-optimized resume PDF tailored to the job description.

It is built for job seekers preparing for technical interviews who want a single workflow that turns "resume + job posting" into a concrete, actionable study plan rather than generic interview tips.

## Why This Project?

Most interview preparation platforms provide generic questions and broad career advice.

Interview Copilot takes a different approach. Users provide their resume and a target job description, and the platform generates a personalized interview preparation report tailored to that specific role.

The platform helps candidates:

- Understand how well their profile matches a role
- Practice job-specific technical and behavioral questions
- Receive AI-powered feedback on interview answers
- Identify skill gaps before interviews
- Follow a structured preparation roadmap
- Generate ATS-friendly resumes aligned with job requirements

The goal is to turn interview preparation into a focused, personalized, and actionable process rather than a one-size-fits-all experience.

## Features

### Authentication
- Email/password registration and login
- JWT issued as an HTTP-only cookie (1-day expiry)
- Stateless logout via a MongoDB token blacklist with TTL-based auto-expiry
- Session rehydration on page load via `GET /api/auth/get-me`

### AI-Generated Interview Reports
- Accepts a resume upload (PDF, parsed server-side) or a free-text self-description
- Generates a 0–100 job match score
- Generates technical and behavioral questions, each with the interviewer's intent and a model answer
- Generates a skill-gap analysis with severity ratings (low/medium/high)
- Generates a multi-day preparation roadmap with daily focus areas and tasks
- Uses Gemini's structured output (`responseSchema`) to enforce a consistent JSON shape

### Practice Arena
- Users can write their own answer to any generated question
- Gemini evaluates the answer against STAR-method structure and job-relevant keywords
- Returns a rating (Excellent / Good / Needs Improvement), strengths, improvement points, and a suggested revision

### Tailored Resume PDF
- Generates an ATS-friendly resume tailored to the job description using Gemini
- Compiles the generated HTML into a PDF server-side with Puppeteer
- Caches the generated HTML on the report document so repeat downloads skip the Gemini call

### Report History
- All generated reports are persisted per user and listed on the dashboard for later review

## Tech Stack

**Frontend**
- React 19, React Router 7
- Vite (build tool / dev server)
- Sass (SCSS) for styling, Context API for state management
- Axios for HTTP requests

**Backend**
- Node.js, Express 5
- Mongoose (MongoDB ODM)
- JWT (`jsonwebtoken`) + `bcryptjs` for authentication
- Multer for file uploads, `pdf-parse` for resume text extraction
- Puppeteer for server-side PDF rendering
- Zod for schema validation

**AI**
- Google Gemini (`gemini-2.5-flash`) via `@google/genai`, used with structured JSON output

**Infrastructure**
- Frontend deployed on Vercel
- Backend deployed on Render

## Architecture

```mermaid
flowchart LR
    subgraph Client["Frontend (React + Vite)"]
        UI[Pages / Components]
        Ctx[Auth & Interview Context]
    end

    subgraph Server["Backend (Express)"]
        Auth[Auth Controller]
        Interview[Interview Controller]
        Mid[JWT Middleware]
        AI[Gemini Service]
        PDF[Puppeteer PDF Service]
    end

    DB[(MongoDB Atlas)]
    Gemini[(Google Gemini API)]

    UI --> Ctx --> Server
    Server --> Mid --> Auth
    Mid --> Interview
    Auth --> DB
    Interview --> DB
    Interview --> AI --> Gemini
    Interview --> PDF
```

### Authentication flow

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend
    participant B as Backend
    participant DB as MongoDB

    U->>F: Submit login form
    F->>B: POST /api/auth/login
    B->>DB: Find user, compare bcrypt hash
    B->>B: Sign JWT (1d expiry)
    B-->>F: Set HTTP-only cookie + user payload
    F->>B: GET /api/auth/get-me (on subsequent loads)
    B->>DB: Check token against blacklist
    B-->>F: Authenticated user
```

### Report generation flow

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend
    participant B as Backend
    participant G as Gemini API
    participant DB as MongoDB

    U->>F: Submit job description + resume/self-description
    F->>B: POST /api/interview/
    B->>B: Extract resume text (pdf-parse, if PDF uploaded)
    B->>G: Generate report (responseSchema enforced)
    G-->>B: Structured JSON (questions, skill gaps, plan)
    B->>DB: Save InterviewReport
    B-->>F: Return report
```

## Folder Structure

```
interview-ai/
├── Backend/
│   ├── server.js                  # Entry point: loads env, connects DB, starts server
│   └── src/
│       ├── app.js                 # Express app, CORS config, route mounting
│       ├── config/database.js     # MongoDB connection
│       ├── controllers/           # auth.controller.js, interview.controller.js
│       ├── middlewares/           # JWT auth middleware, Multer file middleware
│       ├── models/                # User, InterviewReport, Blacklist (Mongoose schemas)
│       ├── routes/                # auth.routes.js, interview.routes.js
│       └── services/ai.service.js # Gemini calls + Puppeteer PDF generation
│
├── Frontend/
│   ├── index.html
│   └── src/
│       ├── App.jsx                # Root providers
│       ├── app.routes.jsx         # React Router route table
│       ├── main.jsx                # React DOM entry
│       └── features/
│           ├── auth/               # Login/Register pages, auth context, useAuth hook
│           └── interview/          # Dashboard, report viewer, practice arena, PDF modal
│
└── render.yaml                    # Render.com deployment manifest
```

## Environment Variables

### Backend (`Backend/.env`)

| Variable | Required | Description |
|---|---|---|
| `MONGO_URI` | Yes | MongoDB connection string (e.g. `mongodb+srv://user:pass@cluster.mongodb.net/dbname`) |
| `JWT_SECRET` | Yes | Secret used to sign/verify JWTs |
| `GOOGLE_GENAI_API_KEY` | Yes | API key for the Google Gemini API |
| `FRONTEND_URL` | Yes | Allowed CORS origin for the frontend (e.g. `http://localhost:5173`) |
| `PORT` | No | Server port, defaults to `5000` |
| `NODE_ENV` | No | `development` or `production` — controls cookie `secure`/`sameSite` behavior |

### Frontend (`Frontend/.env`)

| Variable | Required | Description |
|---|---|---|
| `VITE_API_URL` | No | Backend base URL, defaults to `http://localhost:5000` |

## Installation

```bash
git clone https://github.com/gativarshney/interview-ai.git
cd interview-ai

# Backend
cd Backend
npm install
cp .env.example .env   # create and fill in MONGO_URI, JWT_SECRET, GOOGLE_GENAI_API_KEY, FRONTEND_URL
npm run dev             # starts on http://localhost:5000

# Frontend (in a separate terminal)
cd ../Frontend
npm install
cp .env.example .env   # optional: set VITE_API_URL if not using the default
npm run dev              # starts on http://localhost:5173
```

> No `.env.example` files currently exist in the repository — create `.env` in each directory using the variable tables above.

## Usage

1. Register or log in.
2. On the dashboard, paste a job description and either upload a resume (PDF) or write a self-description.
3. Submit to generate a report containing a match score, technical/behavioral questions, skill gaps, and a study roadmap.
4. Open a report to review questions, expand each one to see the interviewer's intent and a model answer, or switch to practice mode to write your own answer and receive AI feedback.
5. Download a tailored, ATS-optimized resume PDF from the report view.

## API Documentation

### Auth (`/api/auth`)

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register` | Public | Register with `username`, `email`, `password` |
| POST | `/api/auth/login` | Public | Log in with `email`, `password`; sets JWT cookie |
| GET | `/api/auth/logout` | Public | Blacklists current token and clears the cookie |
| GET | `/api/auth/get-me` | Private | Returns the authenticated user |

### Interview (`/api/interview`)

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/interview/` | Private | Generate a report from a job description and resume/self-description |
| GET | `/api/interview/` | Private | List all reports for the authenticated user |
| GET | `/api/interview/report/:interviewId` | Private | Fetch a single report by ID |
| POST | `/api/interview/resume/pdf/:interviewReportId` | Private | Generate (or fetch cached) tailored resume PDF |
| POST | `/api/interview/practice/evaluate` | Private | Evaluate a practice answer for a given question |

Private routes require a valid JWT, supplied via the `token` HTTP-only cookie and validated against the blacklist on every request.

## Database Schema

MongoDB via Mongoose, three collections:

- **users** — `username` (unique), `email` (unique), `password` (bcrypt hash)
- **InterviewReport** — references `user`; stores `jobDescription`, `resume`, `selfDescription`, `title`, `matchScore`, embedded arrays of `technicalQuestions`, `behavioralQuestions`, `skillGaps`, `preparationPlan`, and a cached `tailoredResumeHtml`
- **blacklistTokens** — `token`, with a TTL index so blacklisted JWTs are removed automatically once expired

Report sub-documents (questions, skill gaps, plan days) are embedded rather than referenced, since they are only ever read or written as part of their parent report.

## Key Technical Decisions

- **JWT in an HTTP-only cookie + blacklist, instead of plain sessions** — avoids server-side session storage while still allowing logout to immediately invalidate a token, by blacklisting it until natural expiry.
- **Gemini structured output (`responseSchema`)** instead of free-form prompting — keeps AI output in a fixed JSON shape the database schema can directly accept, reducing parsing/validation failures.
- **Server-side Puppeteer PDF rendering** instead of a client-side PDF library — lets the resume be generated as styled HTML by Gemini and rendered to PDF with full CSS support, then cached on the report to avoid repeat AI calls.

## Deployment

- **Frontend** — deployed on Vercel; `Frontend/vercel.json` rewrites all paths to `index.html` to support client-side routing.
- **Backend** — deployed on Render via `render.yaml`, which builds with `npm install` and starts with `npm start` from the `Backend` directory. `JWT_SECRET` is auto-generated by Render; `MONGO_URI`, `GOOGLE_GENAI_API_KEY`, and `FRONTEND_URL` must be set manually in the Render dashboard.

## Security Considerations

- Passwords hashed with bcrypt before storage.
- JWTs stored in `httpOnly` cookies (not accessible to client-side JS), with `secure`/`sameSite` flags adjusted based on `NODE_ENV`.
- Logout invalidates the token server-side via a blacklist collection, rather than relying solely on client-side cookie removal.
- CORS is restricted to a configured `FRONTEND_URL` plus local dev origins.

## Roadmap

### Implemented
- Authentication (register/login/logout, JWT + blacklist)
- AI-generated interview reports (questions, skill gaps, roadmap, match score)
- Practice arena with AI-graded feedback
- Tailored, cached, ATS-optimized resume PDF generation
- Per-user report history

### Planned
- Automated test coverage (unit/integration)
- CI/CD pipeline
- Functional footer pages (privacy policy, terms of service, help center are currently placeholder links)
- DOCX resume parsing (PDF parsing is implemented; DOCX upload is accepted but not fully processed)

## Contributing

Issues and pull requests are welcome. Before submitting a change:

1. Fork the repository and create a feature branch.
2. Keep backend and frontend changes isolated where possible.
3. Run `npm run lint` in `Frontend` before opening a PR.
4. Describe the change and its motivation clearly in the PR description.

