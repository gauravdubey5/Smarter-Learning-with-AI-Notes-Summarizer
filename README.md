# 🚀 AI Notes Summarizer Web App

An advanced **AI-powered web application** that allows users to summarize text and PDF documents efficiently using state-of-the-art NLP models.

---

## 📌 Overview

This project is a **full-stack AI application** designed to help users quickly extract meaningful insights from large amounts of text.

Unlike basic summarizers, this system includes:

* 🔐 User authentication system
* 📊 Dashboard with analytics
* 📄 PDF summarization
* 🧠 AI-based multi-stage summarization
* 📜 History tracking

---

## ✨ Key Features

### 🧠 AI Text Summarization

* Uses **HuggingFace Transformers (BART model)**
* Dynamic summary length adjustment
* Handles both short & long text efficiently

### 📄 PDF Summarization

* Upload PDF → extract text → generate summary
* Automatic chunking for large documents

### 🔐 Authentication System

* User signup & login
* Password hashing (SHA-256)
* Forgot password & reset functionality

### 📊 User Dashboard

* Track summary usage
* View recent activity
* Daily summary analytics

### 🕓 History Management

* Stores all summaries in SQLite database
* View past summaries anytime

### 📥 Export Features

* Download summary as PDF
* Clean formatted output

### 📂 File Upload API

* Supports `.pdf` and `.txt`
* Secure file handling with auto deletion

---

## 🛠️ Tech Stack

### 🔹 Backend

* Python (Flask)
* SQLite (Database)
* HuggingFace Transformers (BART Model)

### 🔹 Frontend

* HTML, CSS, JavaScript
* Jinja2 Templates

### 🔹 Libraries Used

* `transformers`
* `torch`
* `PyPDF2`
* `reportlab`
* `werkzeug`

---

## 📂 Project Structure

```id="code1"
final_project/
│── app.py
│── users.db
│── static/
│   ├── uploads/
│   ├── scripts.js
│   └── style.css
│── templates/
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── profile.html
│   ├── history.html
│   ├── text_sum.html
│   ├── pdf_sum.html
│   ├── team.html
│   └── ...
```

---

## ⚙️ How It Works

1. User logs in
2. Inputs text OR uploads PDF
3. System processes input
4. AI model generates summary
5. Summary is stored in database
6. User can download or view history

---

## 🧠 Core AI Logic

* Uses `sshleifer/distilbart-cnn-12-6` model 
* Splits large text into chunks
* Performs **multi-stage summarization**
* Re-summarizes combined output for better accuracy

---

## 🚀 Installation & Setup

### 1️⃣ Clone Repository

```bash
git clone https://github.com/gauravdubey5/Smarter-Learning-with-AI-Notes-Summarizer.git
cd Smarter-Learning-with-AI-Notes-Summarizer
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Run Application

```bash
python app.py
```

---

## 🌐 Usage

* Go to `http://localhost:7860`
* Login / Signup
* Use:

  * Text Summarizer
  * PDF Summarizer
* Download results

---

## 🔥 Unique Features (USP)

* ⚡ Dynamic summary length adjustment
* 🧩 Chunk-based processing for large inputs
* 🔄 Multi-stage summarization pipeline
* 📊 Built-in analytics dashboard
* 🔐 Full authentication system

---

## 🚀 Future Enhancements

### 🤖 Advanced AI Capabilities

* Context-aware summarization (better understanding of long documents)
* Multiple summary modes (short / detailed / bullet points)
* Keyword & keyphrase extraction
* Question-answering from summarized content

### 📄 File & Content Support

* Support for DOCX, PPT, and web articles
* YouTube video summarization (via transcript extraction)
* Real-time webpage summarizer (Chrome Extension)

### 🎤 Voice & Accessibility

* Text-to-Speech (listen to summaries)
* Speech-to-Text (voice input for summarization)
* Accessibility-friendly UI for visually impaired users

### 📊 Analytics & Personalization

* Personalized summary recommendations
* User behavior tracking & insights
* Smart dashboard with performance stats

### ☁️ Scalability & DevOps

* Docker containerization
* CI/CD pipeline (GitHub Actions)
* Cloud deployment (AWS / Azure / GCP)
* Load balancing & API scaling

### 🔐 Security Enhancements

* JWT-based authentication
* OAuth login (Google/GitHub)
* Rate limiting & API protection

### 📱 UI/UX Improvements

* Fully responsive mobile-first design
* Dark mode & theme customization
* Notion-style modern interface

### 🌍 Global Features

* Multi-language summarization
* Translation + summarization combo

---

## 💼 Use Case

* Students summarizing notes
* Researchers analyzing documents
* Professionals reviewing reports
* Anyone saving time while reading

---

## 👨‍💻 Team

* Gaurav (Leader & Backend)
* Ujjwal (Leader & Backend)
* Himanshu (Frontend)
* Shivanand (Frontend)
* Vishal (Database)

---

## 📜 License

This project is open-source under the MIT License.

---

## ⭐ Support

If you like this project, give it a ⭐ on GitHub!

---
