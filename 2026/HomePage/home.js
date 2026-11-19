(function () {
    var buttonContainer = document.getElementById("project-buttons");
    if (!buttonContainer) {
        return;
    }

    var buttons = buttonContainer.querySelectorAll(".project-button");
    buttons.forEach(function (button, index) {
        button.classList.add("reveal");
        setTimeout(function () {
            button.classList.add("show");
        }, 90 * (index + 1));
    });
})();
