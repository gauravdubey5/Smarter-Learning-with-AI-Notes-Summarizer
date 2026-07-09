from datetime import datetime

from models import db


class Lesson(db.Model):

    __tablename__ = "lessons"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    chapter_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "chapters.id"
        ),
        nullable=False,
        index=True
    )

    title = db.Column(
        db.String(200),
        nullable=False
    )

    content = db.Column(
        db.Text,
        nullable=True
    )

    video_url = db.Column(
        db.String(500),
        nullable=True
    )

    pdf_file = db.Column(
        db.String(255),
        nullable=True
    )

    duration = db.Column(
        db.String(50),
        nullable=False,
        default="10 minutes"
    )

    position = db.Column(
        db.Integer,
        nullable=False,
        default=1
    )

    is_published = db.Column(
        db.Boolean,
        nullable=False,
        default=True
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

    chapter = db.relationship(
        "Chapter",
        back_populates="lessons"
    )

    progress_records = db.relationship(
        "LessonProgress",
        back_populates="lesson",
        cascade="all, delete-orphan",
        lazy=True
    )

    def __repr__(self):

        return (
            f"<Lesson {self.title}>"
        )


class LessonProgress(db.Model):

    __tablename__ = "lesson_progress"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id"
        ),
        nullable=False,
        index=True
    )

    lesson_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "lessons.id"
        ),
        nullable=False,
        index=True
    )

    is_completed = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    completed_at = db.Column(
        db.DateTime,
        nullable=True
    )

    last_accessed_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    lesson = db.relationship(
        "Lesson",
        back_populates="progress_records"
    )

    __table_args__ = (

        db.UniqueConstraint(
            "user_id",
            "lesson_id",
            name="unique_user_lesson_progress"
        ),

    )

    def __repr__(self):

        return (
            f"<LessonProgress "
            f"user={self.user_id} "
            f"lesson={self.lesson_id}>"
        )