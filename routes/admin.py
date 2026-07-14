import os
import uuid

from werkzeug.utils import secure_filename

from models.lesson import Lesson

from functools import wraps
from slugify import slugify

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    current_app
)

from flask_login import (
    login_required,
    current_user
)

from models import db
from models.course import Course
from models.chapter import Chapter
from models.quiz import Quiz

from models.question import Question
from models.option import Option


admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin"
)


def admin_required(function):

    @wraps(function)
    def decorated_function(
        *args,
        **kwargs
    ):

        if current_user.role != "admin":

            flash(
                "Admin access is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "student.dashboard"
                )
            )

        return function(
            *args,
            **kwargs
        )

    return decorated_function


@admin_bp.route(
    "/dashboard"
)
@login_required
@admin_required
def dashboard():

    total_courses = (
        Course.query.count()
    )

    published_courses = (
        Course.query.filter_by(
            is_published=True
        ).count()
    )

    total_chapters = (
        Chapter.query.count()
    )

    recent_courses = (
        Course.query
        .order_by(
            Course.created_at.desc()
        )
        .limit(5)
        .all()
    )

    return render_template(
        "admin/dashboard.html",
        total_courses=total_courses,
        published_courses=published_courses,
        total_chapters=total_chapters,
        recent_courses=recent_courses
    )


@admin_bp.route(
    "/courses"
)
@login_required
@admin_required
def courses():

    all_courses = (
        Course.query
        .order_by(
            Course.created_at.desc()
        )
        .all()
    )

    return render_template(
        "admin/courses.html",
        courses=all_courses
    )


@admin_bp.route(
    "/courses/add",
    methods=["GET", "POST"]
)
@login_required
@admin_required
def add_course():

    if request.method == "POST":

        title = request.form.get(
            "title",
            ""
        ).strip()

        category = request.form.get(
            "category",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        level = request.form.get(
            "level",
            "Beginner"
        )

        duration = request.form.get(
            "duration",
            "Self-paced"
        ).strip()

        is_published = (
            request.form.get(
                "is_published"
            )
            == "on"
        )

        if (
            not title
            or not category
            or not description
        ):

            flash(
                "Title, category and description are required.",
                "danger"
            )

            return redirect(
                url_for(
                    "admin.add_course"
                )
            )

        base_slug = slugify(
            title
        )

        slug = base_slug

        number = 1

        while Course.query.filter_by(
            slug=slug
        ).first():

            slug = (
                f"{base_slug}-{number}"
            )

            number += 1

        course = Course(
            title=title,
            slug=slug,
            category=category,
            description=description,
            level=level,
            duration=duration,
            is_published=is_published
        )

        db.session.add(
            course
        )

        db.session.commit()

        flash(
            "Course created successfully.",
            "success"
        )

        return redirect(
            url_for(
                "admin.courses"
            )
        )

    return render_template(
        "admin/course_form.html",
        course=None
    )


@admin_bp.route(
    "/courses/<int:course_id>/edit",
    methods=["GET", "POST"]
)
@login_required
@admin_required
def edit_course(
    course_id
):

    course = db.get_or_404(
        Course,
        course_id
    )

    if request.method == "POST":

        course.title = (
            request.form.get(
                "title",
                ""
            ).strip()
        )

        course.category = (
            request.form.get(
                "category",
                ""
            ).strip()
        )

        course.description = (
            request.form.get(
                "description",
                ""
            ).strip()
        )

        course.level = (
            request.form.get(
                "level",
                "Beginner"
            )
        )

        course.duration = (
            request.form.get(
                "duration",
                "Self-paced"
            ).strip()
        )

        course.is_published = (
            request.form.get(
                "is_published"
            )
            == "on"
        )

        db.session.commit()

        flash(
            "Course updated successfully.",
            "success"
        )

        return redirect(
            url_for(
                "admin.courses"
            )
        )

    return render_template(
        "admin/course_form.html",
        course=course
    )


@admin_bp.post(
    "/courses/<int:course_id>/delete"
)
@login_required
@admin_required
def delete_course(
    course_id
):

    course = db.get_or_404(
        Course,
        course_id
    )

    db.session.delete(
        course
    )

    db.session.commit()

    flash(
        "Course deleted successfully.",
        "success"
    )

    return redirect(
        url_for(
            "admin.courses"
        )
    )


@admin_bp.route(
    "/courses/<int:course_id>/chapters",
    methods=["GET", "POST"]
)
@login_required
@admin_required
def manage_chapters(
    course_id
):

    course = db.get_or_404(
        Course,
        course_id
    )

    if request.method == "POST":

        title = request.form.get(
            "title",
            ""
        ).strip()

        description = (
            request.form.get(
                "description",
                ""
            ).strip()
        )

        position = (
            request.form.get(
                "position",
                type=int
            )
        )

        if not title:

            flash(
                "Chapter title is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "admin.manage_chapters",
                    course_id=course.id
                )
            )

        if not position:

            position = (
                len(
                    course.chapters
                )
                + 1
            )

        chapter = Chapter(
            course_id=course.id,
            title=title,
            description=description,
            position=position,
            is_published=True
        )

        db.session.add(
            chapter
        )

        db.session.commit()

        flash(
            "Chapter added successfully.",
            "success"
        )

        return redirect(
            url_for(
                "admin.manage_chapters",
                course_id=course.id
            )
        )

    return render_template(
        "admin/chapters.html",
        course=course
    )


@admin_bp.post(
    "/chapters/<int:chapter_id>/delete"
)
@login_required
@admin_required
def delete_chapter(
    chapter_id
):

    chapter = db.get_or_404(
        Chapter,
        chapter_id
    )

    course_id = (
        chapter.course_id
    )

    db.session.delete(
        chapter
    )

    db.session.commit()

    flash(
        "Chapter deleted successfully.",
        "success"
    )

    return redirect(
        url_for(
            "admin.manage_chapters",
            course_id=course_id
        )
    )

ALLOWED_PDF_EXTENSIONS = {
    "pdf"
}


def allowed_pdf(
    filename
):

    return (

        "." in filename

        and

        filename
        .rsplit(
            ".",
            1
        )[1]
        .lower()

        in ALLOWED_PDF_EXTENSIONS

    )


def save_lesson_pdf(
    pdf_file
):

    if (
        not pdf_file
        or not pdf_file.filename
    ):

        return None

    if not allowed_pdf(
        pdf_file.filename
    ):

        return None

    original_name = secure_filename(
        pdf_file.filename
    )

    unique_name = (

        f"{uuid.uuid4().hex}_"
        f"{original_name}"

    )

    pdf_folder = os.path.join(

        current_app.root_path,

        "uploads",

        "notes"

    )

    os.makedirs(
        pdf_folder,
        exist_ok=True
    )

    pdf_path = os.path.join(
        pdf_folder,
        unique_name
    )

    pdf_file.save(
        pdf_path
    )

    return unique_name


@admin_bp.route(
    "/chapters/<int:chapter_id>/lessons"
)
@login_required
@admin_required
def manage_lessons(
    chapter_id
):

    chapter = db.get_or_404(
        Chapter,
        chapter_id
    )

    return render_template(
        "admin/lessons.html",
        chapter=chapter
    )


@admin_bp.route(
    "/chapters/<int:chapter_id>/lessons/add",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
@admin_required
def add_lesson(
    chapter_id
):

    chapter = db.get_or_404(
        Chapter,
        chapter_id
    )

    if request.method == "POST":

        title = request.form.get(
            "title",
            ""
        ).strip()

        content = request.form.get(
            "content",
            ""
        ).strip()

        video_url = request.form.get(
            "video_url",
            ""
        ).strip()

        duration = request.form.get(
            "duration",
            "10 minutes"
        ).strip()

        position = request.form.get(
            "position",
            type=int
        )

        is_published = (

            request.form.get(
                "is_published"
            )

            == "on"

        )

        pdf = request.files.get(
            "pdf_file"
        )

        if not title:

            flash(
                "Lesson title is required.",
                "danger"
            )

            return redirect(

                url_for(
                    "admin.add_lesson",
                    chapter_id=chapter.id
                )

            )

        if (
            pdf
            and pdf.filename
            and not allowed_pdf(
                pdf.filename
            )
        ):

            flash(
                "Only PDF files are allowed.",
                "danger"
            )

            return redirect(

                url_for(
                    "admin.add_lesson",
                    chapter_id=chapter.id
                )

            )

        if not position:

            position = (

                len(
                    chapter.lessons
                )

                + 1

            )

        pdf_filename = (
            save_lesson_pdf(
                pdf
            )
        )

        lesson = Lesson(

            chapter_id=chapter.id,

            title=title,

            content=content,

            video_url=(
                video_url
                or None
            ),

            pdf_file=pdf_filename,

            duration=(
                duration
                or
                "10 minutes"
            ),

            position=position,

            is_published=is_published

        )

        db.session.add(
            lesson
        )

        db.session.commit()

        flash(
            "Lesson created successfully.",
            "success"
        )

        return redirect(

            url_for(
                "admin.manage_lessons",
                chapter_id=chapter.id
            )

        )

    return render_template(

        "admin/lesson_form.html",

        lesson=None,

        chapter=chapter

    )


@admin_bp.route(
    "/lessons/<int:lesson_id>/edit",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
@admin_required
def edit_lesson(
    lesson_id
):

    lesson = db.get_or_404(
        Lesson,
        lesson_id
    )

    chapter = lesson.chapter

    if request.method == "POST":

        title = request.form.get(
            "title",
            ""
        ).strip()

        if not title:

            flash(
                "Lesson title is required.",
                "danger"
            )

            return redirect(

                url_for(
                    "admin.edit_lesson",
                    lesson_id=lesson.id
                )

            )

        pdf = request.files.get(
            "pdf_file"
        )

        if (
            pdf
            and pdf.filename
            and not allowed_pdf(
                pdf.filename
            )
        ):

            flash(
                "Only PDF files are allowed.",
                "danger"
            )

            return redirect(

                url_for(
                    "admin.edit_lesson",
                    lesson_id=lesson.id
                )

            )

        lesson.title = title

        lesson.content = (

            request.form.get(
                "content",
                ""
            ).strip()

        )

        lesson.video_url = (

            request.form.get(
                "video_url",
                ""
            ).strip()

            or None

        )

        lesson.duration = (

            request.form.get(
                "duration",
                "10 minutes"
            ).strip()

            or

            "10 minutes"

        )

        lesson.position = (

            request.form.get(
                "position",
                type=int
            )

            or

            lesson.position

        )

        lesson.is_published = (

            request.form.get(
                "is_published"
            )

            == "on"

        )

        if (
            pdf
            and pdf.filename
        ):

            new_pdf = save_lesson_pdf(
                pdf
            )

            if new_pdf:

                if lesson.pdf_file:

                    old_pdf_path = (
                        os.path.join(

                            current_app.root_path,

                            "uploads",

                            "notes",

                            lesson.pdf_file

                        )
                    )

                    if os.path.exists(
                        old_pdf_path
                    ):

                        os.remove(
                            old_pdf_path
                        )

                lesson.pdf_file = (
                    new_pdf
                )

        db.session.commit()

        flash(
            "Lesson updated successfully.",
            "success"
        )

        return redirect(

            url_for(
                "admin.manage_lessons",
                chapter_id=chapter.id
            )

        )

    return render_template(

        "admin/lesson_form.html",

        lesson=lesson,

        chapter=chapter

    )


@admin_bp.post(
    "/lessons/<int:lesson_id>/delete"
)
@login_required
@admin_required
def delete_lesson(
    lesson_id
):

    lesson = db.get_or_404(
        Lesson,
        lesson_id
    )

    chapter_id = (
        lesson.chapter_id
    )

    if lesson.pdf_file:

        pdf_path = os.path.join(

            current_app.root_path,

            "uploads",

            "notes",

            lesson.pdf_file

        )

        if os.path.exists(
            pdf_path
        ):

            os.remove(
                pdf_path
            )

    db.session.delete(
        lesson
    )

    db.session.commit()

    flash(
        "Lesson deleted successfully.",
        "success"
    )

    return redirect(

        url_for(
            "admin.manage_lessons",
            chapter_id=chapter_id
        )

    )


# ============================================================
# QUIZ LIST
# ============================================================

@admin_bp.route(
    "/chapters/<int:chapter_id>/quizzes"
)
@login_required
@admin_required
def manage_quizzes(chapter_id):

    chapter = Chapter.query.get_or_404(
        chapter_id
    )

    quizzes = (

        Quiz.query

        .filter_by(
            chapter_id=chapter.id
        )

        .order_by(
            Quiz.created_at.desc()
        )

        .all()

    )

    return render_template(

        "admin/quizzes.html",

        chapter=chapter,

        quizzes=quizzes

    )


# ============================================================
# CREATE QUIZ
# ============================================================

@admin_bp.route(
    "/chapters/<int:chapter_id>/quizzes/add",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
@admin_required
def add_quiz(chapter_id):

    chapter = Chapter.query.get_or_404(
        chapter_id
    )

    if request.method == "POST":

        title = request.form.get(
            "title"
        ).strip()

        description = request.form.get(
            "description"
        )

        instructions = request.form.get(
            "instructions"
        )

        quiz = Quiz(

            chapter_id=chapter.id,

            title=title,

            description=description,

            instructions=instructions,

            time_limit=request.form.get(
                "time_limit",
                type=int
            ),

            passing_percentage=request.form.get(
                "passing_percentage",
                type=int
            ),

            max_attempts=request.form.get(
                "max_attempts",
                type=int
            ),

            negative_marking=(

                request.form.get(
                    "negative_marking"
                )

                ==

                "on"

            ),

            negative_marks=request.form.get(
                "negative_marks",
                type=float
            ),

            shuffle_questions=(

                request.form.get(
                    "shuffle_questions"
                )

                ==

                "on"

            ),

            show_result_immediately=(

                request.form.get(
                    "show_result_immediately"
                )

                ==

                "on"

            ),

            show_correct_answers=(

                request.form.get(
                    "show_correct_answers"
                )

                ==

                "on"

            ),

            is_published=(

                request.form.get(
                    "is_published"
                )

                ==

                "on"

            )

        )

        db.session.add(
            quiz
        )

        db.session.commit()

        flash(

            "Quiz created successfully.",

            "success"

        )

        return redirect(

            url_for(

                "admin.manage_quizzes",

                chapter_id=chapter.id

            )

        )

    return render_template(

        "admin/quiz_form.html",

        chapter=chapter,

        quiz=None

    )


# ============================================================
# EDIT QUIZ
# ============================================================

@admin_bp.route(
    "/quizzes/<int:quiz_id>/edit",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
@admin_required
def edit_quiz(quiz_id):

    quiz = Quiz.query.get_or_404(
        quiz_id
    )

    if request.method == "POST":

        quiz.title = request.form.get(
            "title"
        ).strip()

        quiz.description = request.form.get(
            "description"
        )

        quiz.instructions = request.form.get(
            "instructions"
        )

        quiz.time_limit = request.form.get(
            "time_limit",
            type=int
        )

        quiz.passing_percentage = request.form.get(
            "passing_percentage",
            type=int
        )

        quiz.max_attempts = request.form.get(
            "max_attempts",
            type=int
        )

        quiz.negative_marking = (

            request.form.get(
                "negative_marking"
            )

            ==

            "on"

        )

        quiz.negative_marks = request.form.get(
            "negative_marks",
            type=float
        )

        quiz.shuffle_questions = (

            request.form.get(
                "shuffle_questions"
            )

            ==

            "on"

        )

        quiz.show_result_immediately = (

            request.form.get(
                "show_result_immediately"
            )

            ==

            "on"

        )

        quiz.show_correct_answers = (

            request.form.get(
                "show_correct_answers"
            )

            ==

            "on"

        )

        quiz.is_published = (

            request.form.get(
                "is_published"
            )

            ==

            "on"

        )

        db.session.commit()

        flash(

            "Quiz updated successfully.",

            "success"

        )

        return redirect(

            url_for(

                "admin.manage_quizzes",

                chapter_id=quiz.chapter_id

            )

        )

    return render_template(

        "admin/quiz_form.html",

        chapter=quiz.chapter,

        quiz=quiz

    )


# ============================================================
# DELETE QUIZ
# ============================================================

@admin_bp.post(
    "/quizzes/<int:quiz_id>/delete"
)
@login_required
@admin_required
def delete_quiz(quiz_id):

    quiz = Quiz.query.get_or_404(
        quiz_id
    )

    chapter_id = quiz.chapter_id

    db.session.delete(
        quiz
    )

    db.session.commit()

    flash(

        "Quiz deleted successfully.",

        "success"

    )

    return redirect(

        url_for(

            "admin.manage_quizzes",

            chapter_id=chapter_id

        )

    )


# ============================================================
# PUBLISH / UNPUBLISH
# ============================================================

@admin_bp.post(
    "/quizzes/<int:quiz_id>/toggle"
)
@login_required
@admin_required
def toggle_quiz(quiz_id):

    quiz = Quiz.query.get_or_404(
        quiz_id
    )

    quiz.is_published = (

        not quiz.is_published

    )

    db.session.commit()

    flash(

        "Quiz status updated.",

        "success"

    )

    return redirect(

        url_for(

            "admin.manage_quizzes",

            chapter_id=quiz.chapter_id

        )

    )

@admin_bp.route(
    "/quizzes/<int:quiz_id>/questions"
)
@login_required
@admin_required
def manage_questions(quiz_id):

    quiz = Quiz.query.get_or_404(
        quiz_id
    )

    questions = (

        Question.query

        .filter_by(
            quiz_id=quiz.id
        )

        .order_by(
            Question.position
        )

        .all()

    )

    return render_template(

        "admin/questions.html",

        quiz=quiz,

        questions=questions

    )

@admin_bp.route(
    "/quizzes/<int:quiz_id>/questions/add",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
@admin_required
def add_question(quiz_id):

    quiz = Quiz.query.get_or_404(
        quiz_id
    )

    if request.method == "POST":

        question = Question(

            quiz_id=quiz.id,

            title=request.form.get(
                "title"
            ),

            question_text=request.form.get(
                "question_text"
            ),

            explanation=request.form.get(
                "explanation"
            ),

            difficulty=request.form.get(
                "difficulty"
            ),

            marks=request.form.get(
                "marks",
                type=int
            ),

            position=request.form.get(
                "position",
                type=int
            ),

            question_type=request.form.get(
                "question_type"
            ),

            is_published=True

        )

        db.session.add(
            question
        )

        db.session.commit()

        quiz.update_total_questions()

        quiz.update_total_marks()

        db.session.commit()

        flash(

            "Question added successfully.",

            "success"

        )

        return redirect(

            url_for(

                "admin.manage_questions",

                quiz_id=quiz.id

            )

        )

    return render_template(

        "admin/question_form.html",

        quiz=quiz,

        question=None

    )

@admin_bp.route(
    "/questions/<int:question_id>/edit",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
@admin_required
def edit_question(question_id):

    question = Question.query.get_or_404(
        question_id
    )

    if request.method == "POST":

        question.title = request.form.get(
            "title"
        )

        question.question_text = request.form.get(
            "question_text"
        )

        question.explanation = request.form.get(
            "explanation"
        )

        question.difficulty = request.form.get(
            "difficulty"
        )

        question.marks = request.form.get(
            "marks",
            type=int
        )

        question.position = request.form.get(
            "position",
            type=int
        )

        question.question_type = request.form.get(
            "question_type"
        )

        db.session.commit()

        question.quiz.update_total_marks()

        question.quiz.update_total_questions()

        db.session.commit()

        flash(

            "Question updated successfully.",

            "success"

        )

        return redirect(

            url_for(

                "admin.manage_questions",

                quiz_id=question.quiz_id

            )

        )

    return render_template(

        "admin/question_form.html",

        quiz=question.quiz,

        question=question

    )

@admin_bp.post(
    "/questions/<int:question_id>/delete"
)
@login_required
@admin_required
def delete_question(question_id):

    question = Question.query.get_or_404(
        question_id
    )

    quiz = question.quiz

    db.session.delete(
        question
    )

    db.session.commit()

    quiz.update_total_marks()

    quiz.update_total_questions()

    db.session.commit()

    flash(

        "Question deleted successfully.",

        "success"

    )

    return redirect(

        url_for(

            "admin.manage_questions",

            quiz_id=quiz.id

        )

    )

# ============================================================
# OPTION LIST
# ============================================================

@admin_bp.route(
    "/questions/<int:question_id>/options"
)
@login_required
@admin_required
def manage_options(question_id):

    question = Question.query.get_or_404(question_id)

    options = (
        Option.query
        .filter_by(question_id=question.id)
        .order_by(Option.position)
        .all()
    )

    return render_template(
        "admin/options.html",
        question=question,
        options=options
    )


# ============================================================
# ADD OPTION
# ============================================================

@admin_bp.route(
    "/questions/<int:question_id>/options/add",
    methods=["GET", "POST"]
)
@login_required
@admin_required
def add_option(question_id):

    question = Question.query.get_or_404(question_id)

    if request.method == "POST":

        option = Option(

            question_id=question.id,

            option_key=request.form.get(
                "option_key"
            ),

            option_text=request.form.get(
                "option_text"
            ),

            explanation=request.form.get(
                "explanation"
            ),

            position=request.form.get(
                "position",
                type=int
            ),

            is_correct=(
                request.form.get(
                    "is_correct"
                )
                == "on"
            )

        )

        db.session.add(option)

        db.session.commit()

        flash(
            "Option added successfully.",
            "success"
        )

        return redirect(

            url_for(
                "admin.manage_options",
                question_id=question.id
            )

        )

    return render_template(

        "admin/option_form.html",

        question=question,

        option=None

    )


# ============================================================
# EDIT OPTION
# ============================================================

@admin_bp.route(
    "/options/<int:option_id>/edit",
    methods=["GET", "POST"]
)
@login_required
@admin_required
def edit_option(option_id):

    option = Option.query.get_or_404(option_id)

    if request.method == "POST":

        option.option_key = request.form.get(
            "option_key"
        )

        option.option_text = request.form.get(
            "option_text"
        )

        option.explanation = request.form.get(
            "explanation"
        )

        option.position = request.form.get(
            "position",
            type=int
        )

        option.is_correct = (
            request.form.get(
                "is_correct"
            )
            == "on"
        )

        db.session.commit()

        flash(
            "Option updated successfully.",
            "success"
        )

        return redirect(

            url_for(

                "admin.manage_options",

                question_id=option.question_id

            )

        )

    return render_template(

        "admin/option_form.html",

        question=option.question,

        option=option

    )


# ============================================================
# DELETE OPTION
# ============================================================

@admin_bp.post(
    "/options/<int:option_id>/delete"
)
@login_required
@admin_required
def delete_option(option_id):

    option = Option.query.get_or_404(option_id)

    question_id = option.question_id

    db.session.delete(option)

    db.session.commit()

    flash(
        "Option deleted successfully.",
        "success"
    )

    return redirect(

        url_for(
            "admin.manage_options",
            question_id=question_id
        )

    )