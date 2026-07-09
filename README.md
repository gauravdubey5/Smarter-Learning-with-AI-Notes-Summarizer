# 🎓 SmartLearn AI

> A modern, full-stack learning management platform where students can explore courses, study chapter-wise lessons, watch video lectures, access PDF study materials, take tests, and track their learning progress.

SmartLearn AI was initially developed as an AI Notes Summarizer. It has now been redesigned as a complete student learning and assessment platform with course management, structured learning content, student progress tracking, and role-based administration.

---

## 🚀 Project Overview

SmartLearn AI provides a structured digital learning environment for students.

Administrators can create and manage courses, chapters, lessons, videos, PDFs, and tests. Students can enroll in published courses, study lessons, access learning resources, complete lessons, and monitor their course progress from a personalized dashboard.

---

## ✨ Features

### 👨‍🎓 Student Features

* Secure student registration and login
* Premium personalized student dashboard
* Explore published courses
* View detailed course information
* Enroll in available courses
* View enrolled courses
* Chapter-wise learning system
* Read structured lesson content
* Watch embedded video lectures
* Access PDF study materials
* Previous and next lesson navigation
* Mark lessons as complete
* Automatic course progress calculation
* Track learning progress
* Responsive learning interface
* Student profile management

### 👨‍💼 Admin Features

* Role-based admin authentication
* Premium admin dashboard
* Create new courses
* Edit existing courses
* Delete courses
* Publish or unpublish courses
* Create and manage chapters
* Add chapter descriptions
* Arrange chapters using positions
* Create lessons inside chapters
* Add written study content
* Add video lecture links
* Upload PDF study materials
* Set lesson duration and position
* Publish or save lessons as drafts
* Edit and delete lessons
* Manage all learning content

### 📊 Learning Progress

* Individual lesson completion tracking
* Completed lesson indicators
* Automatic course progress calculation
* Real-time progress percentage
* Course completion tracking
* Last accessed lesson information

---

## 🛠️ Technology Stack

### Backend

* Python
* Flask
* Flask-SQLAlchemy
* Flask-Login
* Werkzeug

### Frontend

* HTML5
* CSS3
* JavaScript
* Jinja2 Templates
* Font Awesome

### Database

* SQLite

### Development Tools

* Git
* GitHub
* Visual Studio Code
* PowerShell

---

## 📁 Project Structure

```text
SmartLearn-AI/
│
├── app.py
├── config.py
├── requirements.txt
├── .env
├── .gitignore
├── README.md
│
├── models/
│   ├── __init__.py
│   ├── user.py
│   ├── course.py
│   ├── chapter.py
│   ├── lesson.py
│   ├── test.py
│   └── result.py
│
├── routes/
│   ├── auth.py
│   ├── student.py
│   ├── courses.py
│   ├── tests.py
│   └── admin.py
│
├── services/
│   ├── ai_service.py
│   └── recommendation_service.py
│
├── templates/
│   ├── base.html
│   ├── index.html
│   │
│   ├── auth/
│   │   ├── login.html
│   │   └── signup.html
│   │
│   ├── student/
│   │   ├── dashboard.html
│   │   ├── courses.html
│   │   ├── course_details.html
│   │   ├── my_courses.html
│   │   ├── learn.html
│   │   ├── test.html
│   │   ├── result.html
│   │   └── profile.html
│   │
│   └── admin/
│       ├── dashboard.html
│       ├── courses.html
│       ├── course_form.html
│       ├── chapters.html
│       ├── lessons.html
│       ├── lesson_form.html
│       └── tests.html
│
├── static/
│   ├── css/
│   │   ├── style.css
│   │   ├── dashboard.css
│   │   ├── courses.css
│   │   ├── learn.css
│   │   └── responsive.css
│   │
│   ├── js/
│   │   ├── main.js
│   │   ├── dashboard.js
│   │   ├── learn.js
│   │   └── test.js
│   │
│   └── images/
│
├── uploads/
│   ├── notes/
│   ├── thumbnails/
│   └── profile/
│
├── database/
│   └── smartlearn.db
│
└── tests/
    ├── test_auth.py
    └── test_quiz.py
```

---

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/gauravdubey5/SmartLearn-AI-Cloud-Native-EdTech-Platform.git
```

### 2. Open the project directory

```bash
cd SmartLearn-AI-Cloud-Native-EdTech-Platform
```

### 3. Create a virtual environment

Windows:

```powershell
python -m venv venv
```

### 4. Activate the virtual environment

PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

Command Prompt:

```cmd
venv\Scripts\activate
```

### 5. Install project dependencies

```powershell
pip install -r requirements.txt
```

### 6. Create the environment file

Create a `.env` file in the root directory:

```env
SECRET_KEY=your-secure-secret-key
DATABASE_URL=sqlite:///database/smartlearn.db
```

### 7. Run the application

```powershell
python app.py
```

### 8. Open SmartLearn AI

Open the following address in your browser:

```text
http://127.0.0.1:5000
```

---

## 👨‍💼 Create an Admin Account

First, create a normal account using the signup page.

Open the Python shell:

```powershell
python
```

Run these commands one by one:

```python
from app import app
from models import db
from models.user import User

ctx = app.app_context()
ctx.push()

user = User.query.filter_by(
    email="your-email@example.com"
).first()

user.role = "admin"

db.session.commit()

print(user.role)
```

The output should be:

```text
admin
```

Exit the Python shell:

```python
exit()
```

Restart the application and log in again.

---

## 🗄️ Database Models

SmartLearn AI currently uses the following database models:

* User
* Course
* Enrollment
* Chapter
* Lesson
* Lesson Progress
* Test
* Question
* Result

The database stores user accounts, role information, courses, student enrollments, chapters, lessons, uploaded learning resources, completion status, course progress, tests, and student results.

---

## 📚 Student Learning Flow

```text
Student Registration
        ↓
Student Login
        ↓
Student Dashboard
        ↓
Explore Courses
        ↓
View Course Details
        ↓
Enroll in Course
        ↓
Open Chapter
        ↓
Study Lesson
        ↓
Watch Video Lecture
        ↓
Read Study Content
        ↓
Open PDF Material
        ↓
Mark Lesson as Complete
        ↓
Automatic Progress Update
        ↓
Complete Course
```

---

## 🔐 Security Features

* Password hashing
* Secure login sessions
* Flask-Login authentication
* Protected student routes
* Protected admin routes
* Role-based access control
* Unique user email validation
* Enrollment validation
* Duplicate enrollment prevention
* Secure uploaded PDF filenames
* File-extension validation

---

## 📱 Responsive Design

SmartLearn AI supports:

* Desktop computers
* Laptops
* Tablets
* Mobile devices

The platform includes responsive course cards, dashboards, lesson readers, navigation menus, forms, and admin management pages.

---

## 🔮 Planned Features

* Online quiz and assessment system
* Multiple-choice questions
* Automatic test evaluation
* Student score and result history
* Test timer
* Leaderboard
* Course certificates
* Student achievements and badges
* AI learning recommendations
* AI study assistant
* Search and course filters
* Email notifications
* Cloud deployment
* Azure database integration
* Docker containerization
* CI/CD automation
* Monitoring and analytics

---

## ☁️ Future Cloud and DevOps Architecture

Planned cloud technologies:

* Microsoft Azure
* Azure App Service
* Azure Database
* Azure Blob Storage
* Terraform
* Docker
* GitHub Actions
* Azure DevOps
* CI/CD Pipelines
* Infrastructure as Code

---

## 🧪 Testing

Run project tests using:

```powershell
pytest
```

Test modules:

```text
tests/
├── test_auth.py
└── test_quiz.py
```

---

## 🤝 Contributing

Contributions, feature suggestions, and improvements are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push the branch
5. Create a pull request

---

## 👨‍💻 Developer

**Gaurav Dubey**

B.Tech Computer Science and Engineering Student
Cloud and DevOps Engineer
Varanasi, Uttar Pradesh, India

Skills:

`Microsoft Azure` • `Terraform` • `Linux` • `Git` • `GitHub` • `Azure DevOps` • `Python` • `Flask` • `Cloud Computing` • `Infrastructure as Code`

---

## 🔗 Connect With Me

* GitHub: `gauravdubey5`
* LinkedIn: `gauravdubey5`
* Portfolio: `gauravdubey.pages.dev`

---

## ⭐ Support

If you find SmartLearn AI useful, consider giving the repository a star.

Your support helps improve the project and encourages future development.

---

## 📄 License

This project is developed for educational and learning purposes.

Copyright © 2026 Gaurav Dubey. All rights reserved.
