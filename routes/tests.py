
from datetime import datetime

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request
)

from flask_login import (
    login_required,
    current_user
)

from models import db

from models.quiz import Quiz
from models.question import Question
from models.quiz_attempt import QuizAttempt
from models.student_answer import StudentAnswer
from models.option import Option

tests_bp = Blueprint(
    "tests",
    __name__,
    url_prefix="/tests"
)


# ============================================================
# START QUIZ
# ============================================================

@tests_bp.route(
    "/<int:quiz_id>/start"
)
@login_required
def start_quiz(quiz_id):

    quiz = Quiz.query.get_or_404(
        quiz_id
    )

    if not quiz.is_published:

        flash(
            "Quiz is not available.",
            "warning"
        )

        return redirect(
            url_for(
                "student.my_courses"
            )
        )

    # -----------------------------------
    # Attempt Limit
    # -----------------------------------

    total_attempts = (

        QuizAttempt.query

        .filter_by(

            user_id=current_user.id,

            quiz_id=quiz.id

        )

        .count()

    )

    if total_attempts >= quiz.max_attempts:

        flash(
            "Maximum attempts reached.",
            "danger"
        )

        return redirect(

            url_for(
                "student.learn",
                chapter_id=quiz.chapter_id
            )

        )

    # -----------------------------------
    # Resume Attempt
    # -----------------------------------

    active_attempt = (

        QuizAttempt.query

        .filter_by(

            user_id=current_user.id,

            quiz_id=quiz.id,

            is_completed=False

        )

        .first()

    )

    if active_attempt:

        flash(
            "Previous attempt resumed.",
            "info"
        )

        return redirect(

            url_for(

                "tests.take_quiz",

                attempt_id=active_attempt.id

            )

        )

    # -----------------------------------
    # New Attempt
    # -----------------------------------

    attempt = QuizAttempt(

        user_id=current_user.id,

        quiz_id=quiz.id,

        attempt_number=total_attempts + 1,

        started_at=datetime.utcnow(),

        total_marks=quiz.total_marks,

        current_question=1

    )

    db.session.add(
        attempt
    )

    quiz.total_attempts += 1

    db.session.commit()

    return redirect(

        url_for(

            "tests.take_quiz",

            attempt_id=attempt.id

        )

    )


# ============================================================
# TAKE QUIZ
# ============================================================

@tests_bp.route(
    "/attempt/<int:attempt_id>"
)
@login_required
def take_quiz(attempt_id):

    attempt = QuizAttempt.query.get_or_404(
        attempt_id
    )

    if attempt.user_id != current_user.id:

        flash(
            "Unauthorized access.",
            "danger"
        )

        return redirect(
            url_for(
                "student.dashboard"
            )
        )

    if attempt.is_completed:

        return redirect(

            url_for(

                "tests.quiz_result",

                attempt_id=attempt.id

            )

        )

    questions = (

        Question.query

        .filter_by(

            quiz_id=attempt.quiz_id,

            is_published=True

        )

        .order_by(
            Question.position
        )

        .all()

    )

    current_question = get_current_question(
    attempt
    )

    palette = build_question_palette(
        attempt
    )

    return render_template(

        "student/take_quiz.html",

        quiz=attempt.quiz,

        attempt=attempt,

        questions=questions,

        current_question=current_question,

        total_questions=len(questions),

        palette=palette

    )
# ============================================================
# SAVE ANSWER
# ============================================================

@tests_bp.route(
    "/attempt/<int:attempt_id>/save",
    methods=["POST"]
)
@login_required
def save_answer(attempt_id):

    attempt = QuizAttempt.query.get_or_404(
        attempt_id
    )

    if attempt.user_id != current_user.id:

        flash(
            "Unauthorized Access.",
            "danger"
        )

        return redirect(
            url_for(
                "student.dashboard"
            )
        )

    if attempt.is_completed:

        flash(
            "Quiz already submitted.",
            "warning"
        )

        return redirect(

            url_for(

                "tests.quiz_result",

                attempt_id=attempt.id

            )

        )

    question_id = request.form.get(
        "question_id",
        type=int
    )

    option_id = request.form.get(
        "option_id",
        type=int
    )

    review = (

        request.form.get(
            "review"
        )

        ==

        "1"

    )

    question = Question.query.get_or_404(
        question_id
    )

    selected_option = None

    if option_id:

        selected_option = Option.query.get_or_404(
            option_id
        )

    answer = StudentAnswer.query.filter_by(

        attempt_id=attempt.id,

        question_id=question.id

    ).first()

    if not answer:

        answer = StudentAnswer(

            attempt_id=attempt.id,

            question_id=question.id

        )

        db.session.add(
            answer
        )

    answer.selected_option = selected_option

    answer.is_reviewed = review

    answer.is_skipped = (

        selected_option is None

    )

    answer.answered_at = datetime.utcnow()

    answer.evaluate()

    attempt.last_saved_at = datetime.utcnow()

    db.session.commit()

    flash(

        "Answer Saved.",

        "success"

    )

    next_question = request.form.get(

        "next_question",

        type=int

    )

    if next_question:

        attempt.current_question = next_question

        db.session.commit()

    return redirect(

        url_for(

            "tests.take_quiz",

            attempt_id=attempt.id

        )

    )

# ============================================================
# NEXT / PREVIOUS QUESTION
# ============================================================

@tests_bp.route(
    "/attempt/<int:attempt_id>/navigate",
    methods=["POST"]
)
@login_required
def navigate_question(attempt_id):

    attempt = QuizAttempt.query.get_or_404(
        attempt_id
    )

    if attempt.user_id != current_user.id:

        flash(
            "Unauthorized access.",
            "danger"
        )

        return redirect(
            url_for(
                "student.dashboard"
            )
        )

    if attempt.is_completed:

        return redirect(
            url_for(
                "tests.quiz_result",
                attempt_id=attempt.id
            )
        )

    action = request.form.get(
        "action"
    )

    total_questions = (

        Question.query

        .filter_by(

            quiz_id=attempt.quiz_id,

            is_published=True

        )

        .count()

    )

    current = attempt.current_question

    # -----------------------------
    # NEXT
    # -----------------------------

    if action == "next":

        if current < total_questions:

            current += 1

    # -----------------------------
    # PREVIOUS
    # -----------------------------

    elif action == "previous":

        if current > 1:

            current -= 1

    # -----------------------------
    # DIRECT JUMP
    # -----------------------------

    elif action == "jump":

        page = request.form.get(
            "page",
            type=int
        )

        if page:

            if page < 1:

                page = 1

            if page > total_questions:

                page = total_questions

            current = page

    attempt.current_question = current

    attempt.last_saved_at = datetime.utcnow()

    db.session.commit()

    return redirect(

        url_for(

            "tests.take_quiz",

            attempt_id=attempt.id

        )

    )


# ============================================================
# GET CURRENT QUESTION
# ============================================================

def get_current_question(attempt):

    questions = (

        Question.query

        .filter_by(

            quiz_id=attempt.quiz_id,

            is_published=True

        )

        .order_by(
            Question.position
        )

        .all()

    )

    if not questions:

        return None

    index = max(
        0,
        attempt.current_question - 1
    )

    if index >= len(questions):

        index = len(questions) - 1

    return questions[index]

# ============================================================
# REVIEW LATER + AUTO SAVE + QUESTION PALETTE
# Paste below navigate_question()
# ============================================================


@tests_bp.post(
    "/attempt/<int:attempt_id>/review/<int:question_id>"
)
@login_required
def toggle_review(
    attempt_id,
    question_id
):

    attempt = QuizAttempt.query.get_or_404(
        attempt_id
    )

    if attempt.user_id != current_user.id:

        flash(
            "Unauthorized Access",
            "danger"
        )

        return redirect(
            url_for(
                "student.dashboard"
            )
        )

    answer = StudentAnswer.query.filter_by(

        attempt_id=attempt.id,

        question_id=question_id

    ).first()

    if not answer:

        answer = StudentAnswer(

            attempt_id=attempt.id,

            question_id=question_id

        )

        db.session.add(
            answer
        )

    answer.is_reviewed = (

        not answer.is_reviewed

    )

    attempt.last_saved_at = datetime.utcnow()

    db.session.commit()

    return redirect(

        url_for(

            "tests.take_quiz",

            attempt_id=attempt.id

        )

    )


# ============================================================
# AUTO SAVE
# ============================================================

@tests_bp.post(
    "/attempt/<int:attempt_id>/autosave"
)
@login_required
def auto_save_attempt(
    attempt_id
):

    attempt = QuizAttempt.query.get_or_404(
        attempt_id
    )

    if attempt.user_id != current_user.id:

        return {

            "success": False

        }, 403

    attempt.last_saved_at = datetime.utcnow()

    db.session.commit()

    return {

        "success": True,

        "saved_at": attempt.last_saved_at.strftime(

            "%H:%M:%S"

        )

    }


# ============================================================
# QUESTION PALETTE
# ============================================================

def build_question_palette(
    attempt
):

    palette = []

    questions = (

        Question.query

        .filter_by(

            quiz_id=attempt.quiz_id,

            is_published=True

        )

        .order_by(
            Question.position
        )

        .all()

    )

    for index, question in enumerate(

        questions,

        start=1

    ):

        answer = StudentAnswer.query.filter_by(

            attempt_id=attempt.id,

            question_id=question.id

        ).first()

        status = "not_visited"

        if index < attempt.current_question:

            status = "visited"

        if answer:

            if answer.is_reviewed:

                status = "review"

            elif answer.answered:

                status = "answered"

            elif answer.is_skipped:

                status = "skipped"

        palette.append({

            "number": index,

            "question_id": question.id,

            "status": status

        })

    return palette


# ============================================================
# SUBMIT QUIZ
# ============================================================

@tests_bp.post(
    "/attempt/<int:attempt_id>/submit"
)
@login_required
def submit_quiz(attempt_id):

    attempt = QuizAttempt.query.get_or_404(
        attempt_id
    )

    if attempt.user_id != current_user.id:

        flash(
            "Unauthorized access.",
            "danger"
        )

        return redirect(
            url_for(
                "student.dashboard"
            )
        )

    if attempt.is_completed:

        return redirect(

            url_for(

                "tests.quiz_result",

                attempt_id=attempt.id

            )

        )

    answers = (

        StudentAnswer.query

        .filter_by(

            attempt_id=attempt.id

        )

        .all()

    )

    # -----------------------------------
    # Statistics
    # -----------------------------------

    total_questions = (

        Question.query

        .filter_by(

            quiz_id=attempt.quiz_id,

            is_published=True

        )

        .count()

    )

    answered = 0

    skipped = 0

    correct = 0

    wrong = 0

    obtained_marks = 0

    negative_marks = 0

    # -----------------------------------
    # Calculate Result
    # -----------------------------------

    for answer in answers:

        if answer.answered:

            answered += 1

        else:

            skipped += 1

        if answer.is_correct:

            correct += 1

            obtained_marks += (

                answer.marks_awarded

            )

        else:

            if answer.answered:

                wrong += 1

                negative_marks += (

                    answer.negative_marks

                )

    final_score = (

        obtained_marks

        -

        negative_marks

    )

    if final_score < 0:

        final_score = 0

    percentage = 0

    if attempt.total_marks > 0:

        percentage = round(

            (

                final_score

                /

                attempt.total_marks

            )

            * 100,

            2

        )

    passed = (

        percentage

        >=

        attempt.quiz.passing_percentage

    )

    # -----------------------------------
    # Save Attempt
    # -----------------------------------

    attempt.total_questions = total_questions

    attempt.answered_questions = answered

    attempt.skipped_questions = skipped

    attempt.correct_answers = correct

    attempt.wrong_answers = wrong

    attempt.obtained_marks = obtained_marks

    attempt.negative_marks = negative_marks

    attempt.score = final_score

    attempt.percentage = percentage

    attempt.is_passed = passed

    attempt.is_completed = True

    attempt.submitted_at = datetime.utcnow()

    # -----------------------------------
    # Quiz Statistics
    # -----------------------------------

    quiz = attempt.quiz

    quiz.total_attempts += 1

    if passed:

        quiz.total_passed += 1

    else:

        quiz.total_failed += 1

    db.session.commit()

    flash(

        "Quiz submitted successfully.",

        "success"

    )

    return redirect(

        url_for(

            "tests.quiz_result",

            attempt_id=attempt.id

        )

    )

# ============================================================
# QUIZ RESULT
# ============================================================

@tests_bp.route(
    "/attempt/<int:attempt_id>/result"
)
@login_required
def quiz_result(attempt_id):

    attempt = QuizAttempt.query.get_or_404(
        attempt_id
    )

    if attempt.user_id != current_user.id:

        flash(
            "Unauthorized access.",
            "danger"
        )

        return redirect(
            url_for(
                "student.dashboard"
            )
        )

    answers = (

        StudentAnswer.query

        .filter_by(

            attempt_id=attempt.id

        )

        .all()

    )

    correct_answers = [

        answer

        for answer in answers

        if answer.is_correct

    ]

    wrong_answers = [

        answer

        for answer in answers

        if (

            answer.answered

            and

            not answer.is_correct

        )

    ]

    skipped_answers = [

        answer

        for answer in answers

        if answer.is_skipped

    ]

    review_answers = [

        answer

        for answer in answers

        if answer.is_reviewed

    ]

    total_time = None

    if (

        attempt.started_at

        and

        attempt.submitted_at

    ):

        seconds = int(

            (

                attempt.submitted_at

                -

                attempt.started_at

            ).total_seconds()

        )

        minutes = seconds // 60

        remain = seconds % 60

        total_time = (

            f"{minutes} min {remain} sec"

        )

    return render_template(

        "student/result.html",

        quiz=attempt.quiz,

        attempt=attempt,

        answers=answers,

        correct_answers=correct_answers,

        wrong_answers=wrong_answers,

        skipped_answers=skipped_answers,

        review_answers=review_answers,

        total_time=total_time

    )