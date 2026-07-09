const learningSidebar =
    document.getElementById(
        "learningSidebar"
    );


const learningMenuButton =
    document.getElementById(
        "learningMenuButton"
    );


const learningOverlay =
    document.getElementById(
        "learningOverlay"
    );


function openLearningMenu() {

    learningSidebar.classList.add(
        "open"
    );

    learningOverlay.classList.add(
        "show"
    );

    document.body.style.overflow =
        "hidden";

}


function closeLearningMenu() {

    learningSidebar.classList.remove(
        "open"
    );

    learningOverlay.classList.remove(
        "show"
    );

    document.body.style.overflow =
        "";

}


if (learningMenuButton) {

    learningMenuButton.addEventListener(

        "click",

        openLearningMenu

    );

}


if (learningOverlay) {

    learningOverlay.addEventListener(

        "click",

        closeLearningMenu

    );

}


document
.querySelectorAll(
    ".learning-lesson-link"
)
.forEach(

    function(link) {

        link.addEventListener(

            "click",

            closeLearningMenu

        );

    }

);