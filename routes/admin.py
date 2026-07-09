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