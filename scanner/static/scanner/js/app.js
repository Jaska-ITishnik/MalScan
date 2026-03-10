// static/js/app.js
(function () {
    const p = document.getElementById("profileMenu");
    if (!p) return;

    const btn = p.querySelector(".profile-btn");
    btn.addEventListener("click", (e) => {
        e.stopPropagation();
        p.classList.toggle("open");
    });

    document.addEventListener("click", () => p.classList.remove("open"));
})();