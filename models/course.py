from datetime import datetime

from models import db


class Course(db.Model):

    __tablename__ = "courses"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(150),
        nullable=False
    )

    slug = db.Column(
        db.String(180),
        unique=True,
        nullable=False,
        index=True
    )

    category = db.Column(
        db.String(100),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    level = db.Column(
        db.String(30),
        nullable=False,
        default="Beginner"
    )

    thumbnail = db.Column(
        db.String(255),
        nullable=False,
        default="default-course.jpg"
    )

    duration = db.Column(
        db.String(50),
        default="Self-paced"
    )

    is_published = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    chapters = db.relationship(
        "Chapter",
        back_populates="course",
        cascade="all, delete-orphan",
        lazy=True,
        order_by="Chapter.position"
    )

    enrollments = db.relationship(
        "Enrollment",
        back_populates="course",
        cascade="all, delete-orphan",
        lazy=True
    )

    @property
    def total_chapters(self):

        return len(
            self.chapters
        )

    def __repr__(self):

        return (
            f"<Course {self.title}>"
        )


class Enrollment(db.Model):

    __tablename__ = "enrollments"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id"
        ),
        nullable=False
    )

    course_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "courses.id"
        ),
        nullable=False
    )

    progress = db.Column(
        db.Float,
        nullable=False,
        default=0.0
    )

    enrolled_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    last_accessed_at = db.Column(
        db.DateTime,
        nullable=True
    )

    course = db.relationship(
        "Course",
        back_populates="enrollments"
    )

    __table_args__ = (

        db.UniqueConstraint(

            "user_id",
            "course_id",

            name=(
                "unique_user_course"
            )

        ),

    )

    def __repr__(self):

        return (

            f"<Enrollment "
            f"user={self.user_id} "
            f"course={self.course_id}>"

        )