from datetime import datetime

from models import db


class StudentAnswer(db.Model):
    """
    Stores one student's answer
    for one question in one quiz attempt.
    """

    __tablename__ = "student_answers"

    # -----------------------------------
    # Primary Key
    # -----------------------------------

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # -----------------------------------
    # Foreign Keys
    # -----------------------------------

    attempt_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "quiz_attempts.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    question_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "questions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    selected_option_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "options.id",
            ondelete="SET NULL"
        ),
        nullable=True,
        index=True
    )

    # -----------------------------------
    # Answer Data
    # -----------------------------------

    answer_text = db.Column(
        db.Text,
        nullable=True
    )

    # -----------------------------------
    # Evaluation
    # -----------------------------------

    is_correct = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    marks_awarded = db.Column(
        db.Float,
        nullable=False,
        default=0
    )

    negative_marks = db.Column(
        db.Float,
        nullable=False,
        default=0
    )

    # -----------------------------------
    # Student Actions
    # -----------------------------------

    is_reviewed = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    is_skipped = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    # -----------------------------------
    # Time
    # -----------------------------------

    answered_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    # -----------------------------------
    # Relationships
    # -----------------------------------

    attempt = db.relationship(
        "QuizAttempt",
        back_populates="answers"
    )

    question = db.relationship(
        "Question",
        back_populates="student_answers"
    )

    selected_option = db.relationship(
        "Option",
        back_populates="student_answers"
    )

    # -----------------------------------
    # Helper Properties
    # -----------------------------------

    @property
    def answered(self):

        return (

            self.selected_option is not None

            or

            bool(self.answer_text)

        )

    @property
    def score(self):

        return (

            self.marks_awarded

            -

            self.negative_marks

        )

    # -----------------------------------
    # Utility Methods
    # -----------------------------------

    def evaluate(self):

        """
        Evaluate MCQ answer.
        """

        if self.selected_option is None:

            self.is_correct = False

            self.marks_awarded = 0

            self.negative_marks = 0

            return

        if self.selected_option.is_correct:

            self.is_correct = True

            self.marks_awarded = self.question.marks

            self.negative_marks = 0

        else:

            self.is_correct = False

            self.marks_awarded = 0

            if self.question.quiz.negative_marking:

                self.negative_marks = (

                    self.question.negative_marks

                )

            else:

                self.negative_marks = 0

    def __repr__(self):

        return (

            f"<StudentAnswer "

            f"{self.id}>"

        )