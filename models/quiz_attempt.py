from datetime import datetime

from models import db


class QuizAttempt(db.Model):
    """
    Student Quiz Attempt

    One Student
        └── Multiple Attempts

    One Quiz
        └── Multiple Attempts

    One Attempt
        └── Multiple Answers
    """

    __tablename__ = "quiz_attempts"

    # ----------------------------------
    # Primary Key
    # ----------------------------------

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # ----------------------------------
    # Foreign Keys
    # ----------------------------------

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    quiz_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "quizzes.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ----------------------------------
    # Attempt Number
    # ----------------------------------

    attempt_number = db.Column(
        db.Integer,
        nullable=False,
        default=1
    )

    # ----------------------------------
    # Timing
    # ----------------------------------

    started_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    submitted_at = db.Column(
        db.DateTime,
        nullable=True
    )

    duration_seconds = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    # ----------------------------------
    # Score
    # ----------------------------------

    total_marks = db.Column(
        db.Float,
        nullable=False,
        default=0
    )

    obtained_marks = db.Column(
        db.Float,
        nullable=False,
        default=0
    )

    percentage = db.Column(
        db.Float,
        nullable=False,
        default=0
    )

    # ----------------------------------
    # Result
    # ----------------------------------

    is_passed = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    is_completed = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    is_auto_submitted = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    # ----------------------------------
    # Resume Support
    # ----------------------------------

    last_saved_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    current_question = db.Column(
        db.Integer,
        default=1
    )

    # ----------------------------------
    # Anti Cheat Ready
    # ----------------------------------

    tab_switches = db.Column(
        db.Integer,
        default=0
    )

    fullscreen_exits = db.Column(
        db.Integer,
        default=0
    )

    warnings = db.Column(
        db.Integer,
        default=0
    )

    # ----------------------------------
    # Review
    # ----------------------------------

    reviewed = db.Column(
        db.Boolean,
        default=False
    )

    feedback = db.Column(
        db.Text,
        nullable=True
    )

    # ----------------------------------
    # Relationships
    # ----------------------------------

    user = db.relationship(
        "User",
        back_populates="quiz_attempts"
    )

    quiz = db.relationship(
        "Quiz",
        back_populates="attempts"
    )

    answers = db.relationship(
    "StudentAnswer",
    back_populates="attempt",
    cascade="all, delete-orphan",
    lazy=True
)

    # ----------------------------------
    # Helper Properties
    # ----------------------------------

    @property
    def answered_questions(self):

        return len(self.answers)

    @property
    def unanswered_questions(self):

        return max(
            self.quiz.question_count
            - self.answered_questions,
            0
        )

    @property
    def completion_percentage(self):

        if self.quiz.question_count == 0:
            return 0

        return round(

            (
                self.answered_questions
                /
                self.quiz.question_count
            ) * 100,

            2

        )

    @property
    def time_taken_minutes(self):

        return round(
            self.duration_seconds / 60,
            2
        )

    # ----------------------------------
    # Utility Methods
    # ----------------------------------

    def calculate_percentage(self):

        if self.total_marks == 0:

            self.percentage = 0

        else:

            self.percentage = round(

                (
                    self.obtained_marks
                    /
                    self.total_marks
                ) * 100,

                2

            )

    def calculate_result(self):

        self.calculate_percentage()

        self.is_passed = (

            self.percentage

            >=

            self.quiz.passing_percentage

        )

    def finish_attempt(
        self,
        auto_submit=False
    ):

        self.submitted_at = datetime.utcnow()

        self.is_completed = True

        self.is_auto_submitted = auto_submit

        self.duration_seconds = int(

            (
                self.submitted_at
                -
                self.started_at
            ).total_seconds()

        )

        self.calculate_result()

    def __repr__(self):

        return (

            f"<QuizAttempt "

            f"{self.id}>"

        )