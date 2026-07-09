from datetime import datetime

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    send_from_directory,
    current_app
)

from flask_login import (
    login_required,
    current_user
)

from models import db
from models.course import Course, Enrollment
from models.lesson import Lesson, LessonProgress


student_bp = Blueprint(
    "student",
    __name__,
    url_prefix="/student"
)


def calculate_course_progress(
    user_id,
    course
):

    all_lessons = []

    for chapter in course.chapters:

        if chapter.is_published:

            for lesson in chapter.lessons:

                if lesson.is_published:

                    all_lessons.append(
                        lesson
                    )

    total_lessons = len(
        all_lessons
    )

    if total_lessons == 0:

        return 0

    lesson_ids = [

        lesson.id

        for lesson
        in all_lessons

    ]

    completed_lessons = (

        LessonProgress.query

        .filter(

            LessonProgress.user_id
            == user_id,

            LessonProgress.lesson_id
            .in_(
                lesson_ids
            ),

            LessonProgress.is_completed
            .is_(
                True
            )

        )

        .count()

    )

    progress = (

        completed_lessons

        / total_lessons

    ) * 100

    return round(
        progress,
        2
    )


def update_enrollment_progress(
    user_id,
    course
):

    enrollment = (

        Enrollment.query

        .filter_by(

            user_id=user_id,

            course_id=course.id

        )

        .first()

    )

    if enrollment:

        enrollment.progress = (

            calculate_course_progress(
                user_id,
                course
            )

        )

        db.session.commit()


@student_bp.route(
    "/dashboard"
)
@login_required
def dashboard():

    enrollments = (

        Enrollment.query

        .filter_by(
            user_id=current_user.id
        )

        .order_by(
            Enrollment.enrolled_at.desc()
        )

        .all()

    )

    return render_template(

        "student/dashboard.html",

        enrollments=enrollments,

        enrolled_courses=len(
            enrollments
        ),

        active_enrollment=(

            enrollments[0]

            if enrollments

            else None

        )

    )


@student_bp.route(
    "/learn/<int:lesson_id>"
)
@login_required
def learn_lesson(
    lesson_id
):

    lesson = db.get_or_404(
        Lesson,
        lesson_id
    )

    chapter = (
        lesson.chapter
    )

    course = (
        chapter.course
    )

    if (
        not lesson.is_published
        or
        not chapter.is_published
        or
        not course.is_published
    ):

        flash(
            "This lesson is not available.",
            "danger"
        )

        return redirect(

            url_for(
                "courses.explore"
            )

        )

    enrollment = (

        Enrollment.query

        .filter_by(

            user_id=current_user.id,

            course_id=course.id

        )

        .first()

    )

    if not enrollment:

        flash(

            "Please enroll in this course first.",

            "warning"

        )

        return redirect(

            url_for(

                "courses.course_details",

                slug=course.slug

            )

        )

    progress_record = (

        LessonProgress.query

        .filter_by(

            user_id=current_user.id,

            lesson_id=lesson.id

        )

        .first()

    )

    if not progress_record:

        progress_record = (

            LessonProgress(

                user_id=current_user.id,

                lesson_id=lesson.id,

                is_completed=False,

                last_accessed_at=(

                    datetime.utcnow()

                )

            )

        )

        db.session.add(
            progress_record
        )

    else:

        progress_record.last_accessed_at = (

            datetime.utcnow()

        )

    enrollment.last_accessed_at = (

        datetime.utcnow()

    )

    db.session.commit()

    course_lessons = []

    for current_chapter in course.chapters:

        if current_chapter.is_published:

            for current_lesson in (

                current_chapter.lessons

            ):

                if current_lesson.is_published:

                    course_lessons.append(

                        current_lesson

                    )

    current_index = (

        course_lessons.index(
            lesson
        )

    )

    previous_lesson = (

        course_lessons[
            current_index - 1
        ]

        if current_index > 0

        else None

    )

    next_lesson = (

        course_lessons[
            current_index + 1
        ]

        if current_index

        < len(
            course_lessons
        ) - 1

        else None

    )

    completed_lesson_ids = {

        item.lesson_id

        for item in (

            LessonProgress.query

            .filter_by(

                user_id=current_user.id,

                is_completed=True

            )

            .all()

        )

    }

    youtube_embed_url = None

    if lesson.video_url:

        video_url = (

            lesson.video_url

        )

        if "watch?v=" in video_url:

            video_id = (

                video_url

                .split(
                    "watch?v="
                )[1]

                .split("&")[0]

            )

            youtube_embed_url = (

                "https://www.youtube.com/embed/"

                + video_id

            )

        elif "youtu.be/" in video_url:

            video_id = (

                video_url

                .split(
                    "youtu.be/"
                )[1]

                .split("?")[0]

            )

            youtube_embed_url = (

                "https://www.youtube.com/embed/"

                + video_id

            )

        elif "/embed/" in video_url:

            youtube_embed_url = (

                video_url

            )

    course_progress = (

        calculate_course_progress(

            current_user.id,

            course

        )

    )

    return render_template(

        "student/learn.html",

        lesson=lesson,

        chapter=chapter,

        course=course,

        progress_record=(

            progress_record

        ),

        previous_lesson=(

            previous_lesson

        ),

        next_lesson=(

            next_lesson

        ),

        completed_lesson_ids=(

            completed_lesson_ids

        ),

        youtube_embed_url=(

            youtube_embed_url

        ),

        course_progress=(

            course_progress

        )

    )


@student_bp.post(
    "/lessons/<int:lesson_id>/complete"
)
@login_required
def complete_lesson(
    lesson_id
):

    lesson = db.get_or_404(
        Lesson,
        lesson_id
    )

    course = (

        lesson
        .chapter
        .course

    )

    enrollment = (

        Enrollment.query

        .filter_by(

            user_id=current_user.id,

            course_id=course.id

        )

        .first()

    )

    if not enrollment:

        flash(

            "You are not enrolled in this course.",

            "danger"

        )

        return redirect(

            url_for(
                "courses.explore"
            )

        )

    progress_record = (

        LessonProgress.query

        .filter_by(

            user_id=current_user.id,

            lesson_id=lesson.id

        )

        .first()

    )

    if not progress_record:

        progress_record = (

            LessonProgress(

                user_id=current_user.id,

                lesson_id=lesson.id

            )

        )

        db.session.add(

            progress_record

        )

    progress_record.is_completed = (

        True

    )

    progress_record.completed_at = (

        datetime.utcnow()

    )

    progress_record.last_accessed_at = (

        datetime.utcnow()

    )

    db.session.commit()

    update_enrollment_progress(

        current_user.id,

        course

    )

    flash(

        "Lesson completed successfully! 🎉",

        "success"

    )

    return redirect(

        url_for(

            "student.learn_lesson",

            lesson_id=lesson.id

        )

    )


@student_bp.route(
    "/lesson-pdf/<path:filename>"
)
@login_required
def lesson_pdf(
    filename
):

    pdf_directory = (

        current_app.root_path

        + "/uploads/notes"

    )

    return send_from_directory(

        pdf_directory,

        filename

    )