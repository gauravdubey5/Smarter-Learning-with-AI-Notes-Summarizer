from datetime import datetime

from models import db


class Option(db.Model):
    """
    One Question
        └── Multiple Options

    Example:

    Question:
        What is Azure?

    Options:
        A
        B
        C
        D
    """

    __tablename__ = "options"

    # -------------------------
    # Primary Key
    # -------------------------

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # -------------------------
    # Foreign Key
    # -------------------------

    question_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "questions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # -------------------------
    # Option Content
    # -------------------------

    option_text = db.Column(
        db.Text,
        nullable=False
    )

    image = db.Column(
        db.String(255),
        nullable=True
    )

    explanation = db.Column(
        db.Text,
        nullable=True
    )

    # -------------------------
    # Option Settings
    # -------------------------

    option_key = db.Column(
        db.String(5),
        nullable=False
    )
    # A
    # B
    # C
    # D
    # E

    position = db.Column(
        db.Integer,
        nullable=False,
        default=1
    )

    is_correct = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    # -------------------------
    # Statistics
    # -------------------------

    selected_count = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    # -------------------------
    # Time
    # -------------------------

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # -------------------------
    # Relationships
    # -------------------------

    question = db.relationship(
        "Question",
        back_populates="options"
    )

    student_answers = db.relationship(
    "StudentAnswer",
    back_populates="selected_option",
    lazy=True
)

    # -------------------------
    # Helper Properties
    # -------------------------

    @property
    def label(self):

        return f"{self.option_key}. {self.option_text}"

    @property
    def is_image_option(self):

        return self.image is not None

    # -------------------------
    # Utility
    # -------------------------

    def increment_selected_count(self):

        self.selected_count += 1

    def __repr__(self):

        return (
            f"<Option "
            f"{self.option_key}>"
        )