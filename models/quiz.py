from datetime import datetime

from models import db


class Quiz(db.Model):
    """
    Quiz belongs to one Chapter.

    One Chapter
        └── Multiple Quizzes

    One Quiz
        ├── Multiple Questions
        └── Multiple Student Attempts
    """

    __tablename__ = "quizzes"

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

    chapter_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "chapters.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # -------------------------
    # Quiz Information
    # -------------------------

    title = db.Column(
        db.String(200),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    instructions = db.Column(
        db.Text,
        nullable=True
    )

    # -------------------------
    # Quiz Settings
    # -------------------------

    time_limit = db.Column(
        db.Integer,
        nullable=False,
        default=20
    )
    # Minutes

    passing_percentage = db.Column(
        db.Integer,
        nullable=False,
        default=40
    )

    max_attempts = db.Column(
        db.Integer,
        nullable=False,
        default=3
    )

    total_marks = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    negative_marking = db.Column(
        db.Boolean,
        default=False
    )

    negative_marks = db.Column(
        db.Float,
        default=0.0
    )

    shuffle_questions = db.Column(
        db.Boolean,
        default=False
    )

    show_result_immediately = db.Column(
        db.Boolean,
        default=True
    )

    show_correct_answers = db.Column(
        db.Boolean,
        default=True
    )

    is_published = db.Column(
        db.Boolean,
        default=False
    )

    # -------------------------
    # Statistics
    # -------------------------

    total_questions = db.Column(
        db.Integer,
        default=0
    )

    total_attempts = db.Column(
        db.Integer,
        default=0
    )

    # -------------------------
    # Timestamps
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

    chapter = db.relationship(
        "Chapter",
        back_populates="quizzes"
    )

    questions = db.relationship(
        "Question",
        back_populates="quiz",
        cascade="all, delete-orphan",
        lazy=True,
        order_by="Question.position"
    )

    attempts = db.relationship(
        "QuizAttempt",
        back_populates="quiz",
        cascade="all, delete-orphan",
        lazy=True
    )

    # -------------------------
    # Helper Properties
    # -------------------------

    @property
    def published_questions(self):

        return [

            question

            for question in self.questions

            if question.is_published

        ]

    @property
    def question_count(self):

        return len(
            self.questions
        )

    @property
    def published_question_count(self):

        return len(
            self.published_questions
        )

    @property
    def average_marks(self):

        if not self.attempts:

            return 0

        total = sum(

            attempt.score

            for attempt

            in self.attempts

        )

        return round(

            total / len(self.attempts),

            2

        )

    @property
    def pass_rate(self):

        if not self.attempts:

            return 0

        passed = len(

            [

                attempt

                for attempt

                in self.attempts

                if attempt.is_passed

            ]

        )

        return round(

            passed * 100 / len(self.attempts),

            2

        )

    # -------------------------
    # Utility Methods
    # -------------------------

    def update_total_marks(self):

        self.total_marks = sum(

            question.marks

            for question

            in self.questions

        )

    def update_total_questions(self):

        self.total_questions = len(

            self.questions

        )

    def __repr__(self):

        return (

            f"<Quiz "

            f"{self.title}>"

        )