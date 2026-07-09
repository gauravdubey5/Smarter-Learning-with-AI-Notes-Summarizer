from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user
)

from models import db
from models.user import User


auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth"
)


@auth_bp.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if current_user.is_authenticated:

        return redirect(
            url_for("student.dashboard")
        )

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not name:

            flash(
                "Please enter your name.",
                "danger"
            )

            return redirect(
                url_for("auth.signup")
            )

        if not email:

            flash(
                "Please enter your email.",
                "danger"
            )

            return redirect(
                url_for("auth.signup")
            )

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "danger"
            )

            return redirect(
                url_for("auth.signup")
            )

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return redirect(
                url_for("auth.signup")
            )

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:

            flash(
                "An account with this email already exists.",
                "warning"
            )

            return redirect(
                url_for("auth.login")
            )

        user = User(
            name=name,
            email=email,
            role="student"
        )

        user.set_password(
            password
        )

        db.session.add(
            user
        )

        db.session.commit()

        flash(
            "Account created successfully. Please log in.",
            "success"
        )

        return redirect(
            url_for("auth.login")
        )

    return render_template(
        "auth/signup.html"
    )


@auth_bp.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if current_user.is_authenticated:

        return redirect(
            url_for("student.dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        remember = bool(
            request.form.get("remember")
        )

        user = User.query.filter_by(
            email=email
        ).first()

        if (
            user
            and user.check_password(password)
        ):

            login_user(
                user,
                remember=remember
            )

            flash(
                f"Welcome back, {user.name}!",
                "success"
            )

            if user.role == "admin":

                return redirect(
                    url_for(
                        "admin.dashboard"
                    )
                )

            return redirect(
                url_for(
                    "student.dashboard"
                )
            )

        flash(
            "Invalid email or password.",
            "danger"
        )

    return render_template(
        "auth/login.html"
    )


@auth_bp.route(
    "/logout"
)
@login_required
def logout():

    logout_user()

    flash(
        "You have been logged out.",
        "info"
    )

    return redirect(
        url_for("auth.login")
    )