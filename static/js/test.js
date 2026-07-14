/* ==========================================================
   Professional Countdown Timer
   ========================================================== */

document.addEventListener("DOMContentLoaded", function () {

    // ---------------------------------------
    // Elements
    // ---------------------------------------

    const timer = document.getElementById("timer");

    const progress = document.getElementById(
        "timer-progress"
    );

    const bar = document.getElementById(
        "time-bar"
    );

    const warning = document.getElementById(
        "timer-warning"
    );

    const danger = document.getElementById(
        "timer-danger"
    );

    const card = document.querySelector(
        ".timer-card"
    );

    const submitForm = document.getElementById(
        "submitQuizForm"
    );

    if (
        !timer ||
        !progress ||
        !bar
    ){

        return;

    }

    // ---------------------------------------
    // Configuration
    // ---------------------------------------

    const totalMinutes = Number(

        timer.dataset.minutes

    );

    let totalSeconds = totalMinutes * 60;

    const radius = 70;

    const circumference =

        2 * Math.PI * radius;

    progress.style.strokeDasharray =

        circumference;

    progress.style.strokeDashoffset = 0;

    // ---------------------------------------
    // Format Time
    // ---------------------------------------

    function formatTime(seconds){

        const m = Math.floor(

            seconds / 60

        );

        const s = seconds % 60;

        return (

            String(m).padStart(2,"0")

            +

            ":"

            +

            String(s).padStart(2,"0")

        );

    }

    // ---------------------------------------
    // Update UI
    // ---------------------------------------

    function updateTimer(){

        timer.innerText =

            formatTime(totalSeconds);

        const percent =

            totalSeconds /

            (totalMinutes * 60);

        progress.style.strokeDashoffset =

            circumference *

            (1-percent);

        bar.style.width =

            (percent*100) + "%";

        // ---------------------------
        // Less than 5 min
        // ---------------------------

        if(totalSeconds<=300){

            warning.style.display="block";

            card.classList.add(

                "warning"

            );

        }

        // ---------------------------
        // Less than 1 min
        // ---------------------------

        if(totalSeconds<=60){

            danger.style.display="block";

            card.classList.remove(

                "warning"

            );

            card.classList.add(

                "danger"

            );

        }

        // ---------------------------
        // Auto Submit
        // ---------------------------

        if(totalSeconds<=0){

            clearInterval(interval);

            timer.innerText="00:00";

            alert(

                "Time Over!\nQuiz will be submitted."

            );

            if(submitForm){

                submitForm.submit();

            }

        }

        totalSeconds--;

    }

    updateTimer();

    const interval =

        setInterval(

            updateTimer,

            1000

        );

});


// =========================================
// Highlight Selected Option
// =========================================

document.querySelectorAll(".option-card").forEach(function(card){

    const radio = card.querySelector("input");

    radio.addEventListener("change",function(){

        document.querySelectorAll(".option-card").forEach(function(c){

            c.classList.remove("selected");

        });

        card.classList.add("selected");

    });

});

// =========================================
// Submit Confirmation
// =========================================

function confirmSubmitQuiz(){

    const ok = confirm(

        "Are you sure you want to submit your quiz?\n\nYou won't be able to change your answers afterwards."

    );

    if(ok){

        document.getElementById(

            "submitQuizForm"

        ).submit();

    }

}

