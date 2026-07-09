from datetime import datetime

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash
)

from flask_login import (
    login_required,
    current_user
)

from models import db

from models.course import (
    Course,
    Enrollment
)


courses_bp = Blueprint(
    "courses",
    __name__,
    url_prefix="/courses"
)


@courses_bp.route("/")
@login_required
def explore():

    courses = (
        Course.query
        .filter_by(
            is_published=True
        )
        .order_by(
            Course.created_at.desc()
        )
        .all()
    )

    enrolled_course_ids = {

        enrollment.course_id

        for enrollment
        in current_user.enrollments

    }

    return render_template(
        "student/courses.html",
        courses=courses,
        enrolled_course_ids=enrolled_course_ids
    )


@courses_bp.route(
    "/<slug>"
)
@login_required
def course_details(
    slug
):

    course = (
        Course.query
        .filter_by(
            slug=slug,
            is_published=True
        )
        .first_or_404()
    )

    enrollment = (
        Enrollment.query
        .filter_by(
            user_id=current_user.id,
            course_id=course.id
        )
        .first()
    )

    return render_template(
        "student/course_details.html",
        course=course,
        enrollment=enrollment
    )


@courses_bp.post(
    "/<int:course_id>/enroll"
)
@login_required
def enroll(
    course_id
):

    course = db.get_or_404(
        Course,
        course_id
    )

    if not course.is_published:

        flash(
            "This course is not available.",
            "danger"
        )

        return redirect(
            url_for(
                "courses.explore"
            )
        )

    existing_enrollment = (
        Enrollment.query
        .filter_by(
            user_id=current_user.id,
            course_id=course.id
        )
        .first()
    )

    if existing_enrollment:

        flash(
            "You are already enrolled in this course.",
            "info"
        )

        return redirect(
            url_for(
                "courses.course_details",
                slug=course.slug
            )
        )

    enrollment = Enrollment(
        user_id=current_user.id,
        course_id=course.id,
        progress=0
    )

    db.session.add(
        enrollment
    )

    db.session.commit()

    flash(
        f"You successfully enrolled in {course.title}.",
        "success"
    )

    return redirect(
        url_for(
            "courses.my_courses"
        )
    )


@courses_bp.route(
    "/my-courses"
)
@login_required
def my_courses():

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
        "student/my_courses.html",
        enrollments=enrollments
    )


@courses_bp.post(
    "/<int:course_id>/continue"
)
@login_required
def continue_course(
    course_id
):

    enrollment = (
        Enrollment.query
        .filter_by(
            user_id=current_user.id,
            course_id=course_id
        )
        .first_or_404()
    )

    enrollment.last_accessed_at = (
        datetime.utcnow()
    )

    db.session.commit()

    return redirect(
        url_for(
            "courses.course_details",
            slug=enrollment.course.slug
        )
    )