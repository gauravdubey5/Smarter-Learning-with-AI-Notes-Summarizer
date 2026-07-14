import os

from flask import (
    Flask,
    render_template
)

from flask_login import (
    LoginManager
)

from config import Config

from models import db

from models.user import User

from routes.auth import auth_bp

from routes.student import student_bp

from routes.admin import admin_bp

from models.user import User

from models.course import (
    Course,
    Enrollment
)

from models.chapter import Chapter

from routes.courses import courses_bp
from models.lesson import (
    Lesson,
    LessonProgress
)
from models.quiz import Quiz
from models.question import Question

from models.option import Option

from models.quiz_attempt import QuizAttempt

from models.student_answer import StudentAnswer

login_manager = LoginManager()

login_manager.login_view = (
    "auth.login"
)

login_manager.login_message = (
    "Please log in to access this page."
)

login_manager.login_message_category = (
    "warning"
)


def create_app():

    app = Flask(
        __name__
    )

    app.config.from_object(
        Config
    )

    db.init_app(
        app
    )

    login_manager.init_app(
        app
    )

    app.register_blueprint(
        auth_bp
    )

    app.register_blueprint(
        student_bp
    )

    app.register_blueprint(
        admin_bp
    )

    app.register_blueprint(
        courses_bp
    )

    os.makedirs(
        app.config[
            "UPLOAD_FOLDER"
        ],
        exist_ok=True
    )

    with app.app_context():

        db.create_all()

    @app.route("/")
    def home():

        return render_template(
            "index.html"
        )

    return app


@login_manager.user_loader
def load_user(
    user_id
):

    return db.session.get(
        User,
        int(user_id)
    )


app = create_app()


if __name__ == "__main__":

    app.run(
        debug=True
    )