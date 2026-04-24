function toggleTheme() {
    document.body.classList.toggle("light-mode");
}

document.querySelector("form")?.addEventListener("submit", function () {
    document.getElementById("loading").style.display = "block";
});