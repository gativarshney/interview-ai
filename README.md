# 🚀 Interview AI — Full Stack GenAI Job Preparation Platform

An **AI-powered full stack web application** designed to help users prepare for job interviews through **intelligent resume analysis, skill gap detection, and AI-generated interview questions**.

This project simulates a **real-world job preparation ecosystem**, combining **modern web development + Generative AI** to deliver actionable insights for candidates.

---

## 🌟 Key Highlights

* 🔐 Secure authentication system with JWT & token invalidation
* 📄 Resume upload, parsing & skill extraction
* 🤖 AI-powered interview question generation
* 📊 Skill gap analysis based on job descriptions
* 🧾 ATS-optimized resume generation
* 📑 Dynamic PDF creation using Puppeteer
* ⚡ Scalable full-stack architecture

---

## 🛠 Tech Stack

### Frontend

* React.js (Vite)
* Context API
* Axios

### Backend

* Node.js
* Express.js

### Database

* MongoDB Atlas

### Authentication

* JWT (JSON Web Tokens)
* Token Blacklisting

### AI Integration

* Gemini API

### Other Tools

* Puppeteer (PDF generation)
* Multer (file uploads)
* Zod (schema validation)

---

## 🧠 Core Features

### 🔐 Authentication System

* User registration & login
* Secure session handling with JWT
* Logout using token blacklisting

---

### 📄 Resume Analysis

* Upload resumes (PDF)
* Extract structured data & skills
* Prepare data for AI processing

---

### 🤖 AI Interview Generator

* Generate role-specific interview questions
* Create structured interview reports
* Store and retrieve reports

---

### 📊 Skill Gap Detection

* Compare resume vs job description
* Identify missing skills using AI

---

### 🧾 Resume Builder (ATS-Friendly)

* Generate optimized resumes
* Improve job selection chances

---

### 📑 PDF Generation Pipeline

* Convert AI-generated content into PDFs
* Fully automated backend pipeline

---

## 🏗️ Architecture

```
Client (React)
   ↓
Service Layer (Axios APIs)
   ↓
Backend (Node + Express)
   ↓
AI Layer (Gemini API)
   ↓
Database (MongoDB)
```

---

## 📂 Project Structure

```
client/
 ├── components/
 ├── pages/
 ├── hooks/
 ├── context/
 └── services/

server/
 ├── controllers/
 ├── routes/
 ├── models/
 ├── middleware/
 ├── services/
 └── utils/
```

---

## ⚙️ Installation & Setup

### 1. Clone Repository

```bash
git clone https://github.com/gativarshney/interview-ai.git
cd interview-ai
```

---

### 2. Backend Setup

```bash
cd server
npm install
```

Create `.env` file:

```
PORT=5000
MONGO_URI=your_mongodb_uri
JWT_SECRET=your_secret
GEMINI_API_KEY=your_api_key
```

Run server:

```bash
npm run dev
```

---

### 3. Frontend Setup

```bash
cd client
npm install
npm run dev
```

---

## 🔌 API Overview

### Auth

* `POST /api/auth/register`
* `POST /api/auth/login`
* `POST /api/auth/logout`
* `GET /api/auth/me`

### Interview

* `POST /api/interview/generate`
* `GET /api/interview/:id`
* `GET /api/interview`

### Resume

* `POST /api/resume/generate-pdf`

---

## 🚧 Current Status

> ⚠️ This project is actively under development.

Upcoming improvements:

* UI/UX enhancements
* Advanced AI evaluation logic
* Real-time mock interviews
* Performance optimizations

---

## 🎯 What I Learned

* Building **production-ready full stack systems**
* Implementing **secure authentication flows**
* Integrating **Generative AI into real applications**
* Designing **scalable backend architecture**
* Handling **file uploads & PDF generation pipelines**

---

## 🔮 Future Scope

* 🎤 Voice-based AI mock interviews
* 📈 Performance analytics dashboard
* 🎯 Personalized job recommendations
* 🧠 AI-based learning roadmap
