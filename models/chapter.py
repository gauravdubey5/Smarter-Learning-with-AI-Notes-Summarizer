from datetime import datetime

from models import db


class Chapter(db.Model):

    __tablename__ = "chapters"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    course_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "courses.id"
        ),
        nullable=False,
        index=True
    )

    title = db.Column(
        db.String(180),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    position = db.Column(
        db.Integer,
        nullable=False,
        default=1
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

    course = db.relationship(
        "Course",
        back_populates="chapters"
    )
    lessons = db.relationship(
    "Lesson",
    back_populates="chapter",
    cascade="all, delete-orphan",
    lazy=True,
    order_by="Lesson.position"
    )
    quizzes = db.relationship(
    "Quiz",
    back_populates="chapter",
    cascade="all, delete-orphan",
    lazy=True,
    order_by="Quiz.created_at.desc()"
)

    @property
    def total_lessons(self):

        return len(
            self.lessons
        )

    def __repr__(self):

        return (

            f"<Chapter "
            f"{self.title}>"

        )