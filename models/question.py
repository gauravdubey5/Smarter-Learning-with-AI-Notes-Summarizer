from datetime import datetime

from models import db


class Question(db.Model):
    """
    One Quiz
        └── Multiple Questions

    One Question
        └── Multiple Options
    """

    __tablename__ = "questions"

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

    quiz_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "quizzes.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # -------------------------
    # Question Content
    # -------------------------

    title = db.Column(
        db.String(255),
        nullable=True
    )

    question_text = db.Column(
        db.Text,
        nullable=False
    )

    explanation = db.Column(
        db.Text,
        nullable=True
    )

    image = db.Column(
        db.String(255),
        nullable=True
    )

    # -------------------------
    # Question Type
    # -------------------------

    question_type = db.Column(
        db.String(30),
        nullable=False,
        default="mcq"
    )
    """
    Supported:

    mcq
    multiple_correct
    true_false
    short_answer
    coding
    """

    # -------------------------
    # Difficulty
    # -------------------------

    difficulty = db.Column(
        db.String(20),
        nullable=False,
        default="Easy"
    )

    """
    Easy
    Medium
    Hard
    """

    # -------------------------
    # Marks
    # -------------------------

    marks = db.Column(
        db.Integer,
        nullable=False,
        default=1
    )

    negative_marks = db.Column(
        db.Float,
        nullable=False,
        default=0.0
    )

    # -------------------------
    # Display
    # -------------------------

    position = db.Column(
        db.Integer,
        nullable=False,
        default=1
    )

    is_required = db.Column(
        db.Boolean,
        default=True
    )

    is_published = db.Column(
        db.Boolean,
        default=True
    )

    # -------------------------
    # Statistics
    # -------------------------

    total_attempts = db.Column(
        db.Integer,
        default=0
    )

    correct_attempts = db.Column(
        db.Integer,
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

    quiz = db.relationship(
        "Quiz",
        back_populates="questions"
    )

    options = db.relationship(
        "Option",
        back_populates="question",
        cascade="all, delete-orphan",
        lazy=True,
        order_by="Option.position"
    )

    student_answers = db.relationship(
    "StudentAnswer",
    back_populates="question",
    cascade="all, delete-orphan",
    lazy=True
)

    # -------------------------
    # Helper Properties
    # -------------------------

    @property
    def option_count(self):

        return len(
            self.options
        )

    @property
    def correct_options(self):

        return [

            option

            for option

            in self.options

            if option.is_correct

        ]

    @property
    def correct_option_count(self):

        return len(
            self.correct_options
        )
    
    @property
    def ordered_options(self):

        return sorted(

            self.options,

            key=lambda option: option.position

        )

    @property
    def success_rate(self):

        if self.total_attempts == 0:

            return 0

        return round(

            (

                self.correct_attempts
                /
                self.total_attempts

            ) * 100,

            2

        )

    # -------------------------
    # Utility Methods
    # -------------------------

    def has_single_correct_answer(self):

        return (

            self.correct_option_count
            == 1

        )

    def has_multiple_correct_answers(self):

        return (

            self.correct_option_count
            > 1

        )

    def __repr__(self):

        return (

            f"<Question "

            f"{self.id}>"

        )