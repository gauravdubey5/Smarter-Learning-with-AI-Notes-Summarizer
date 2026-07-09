function togglePassword(
    inputId,
    button
) {

    const input =
        document.getElementById(
            inputId
        );


    const icon =
        button.querySelector(
            "i"
        );


    if (
        input.type === "password"
    ) {

        input.type = "text";

        icon.classList.remove(
            "fa-eye"
        );

        icon.classList.add(
            "fa-eye-slash"
        );

    }

    else {

        input.type = "password";

        icon.classList.remove(
            "fa-eye-slash"
        );

        icon.classList.add(
            "fa-eye"
        );

    }

}


setTimeout(
    () => {

        document
            .querySelectorAll(
                ".flash-message"
            )
            .forEach(

                message => {

                    message.remove();

                }

            );

    },

    5000

);