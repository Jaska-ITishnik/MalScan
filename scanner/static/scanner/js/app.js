// static/js/app.js
(function () {
    /* ===== Profile dropdown ===== */
    const p = document.getElementById("profileMenu");
    if (p) {
        const btn = p.querySelector(".profile-btn");
        btn.addEventListener("click", (e) => {
            e.stopPropagation();
            p.classList.toggle("open");
        });
        document.addEventListener("click", () => p.classList.remove("open"));
    }

    /* ===== Hamburger / mobile nav ===== */
    const hamburger = document.getElementById("hamburgerBtn");
    const nav = document.getElementById("mainNav");
    const overlay = document.getElementById("mobileOverlay");

    if (!hamburger || !nav || !overlay) return;

    function openNav() {
        nav.classList.add("mobile-open");
        hamburger.classList.add("open");
        overlay.classList.add("open");
        hamburger.setAttribute("aria-expanded", "true");
        document.body.style.overflow = "hidden";
    }

    function closeNav() {
        nav.classList.remove("mobile-open");
        hamburger.classList.remove("open");
        overlay.classList.remove("open");
        hamburger.setAttribute("aria-expanded", "false");
        document.body.style.overflow = "";
    }

    hamburger.addEventListener("click", (e) => {
        e.stopPropagation();
        if (nav.classList.contains("mobile-open")) {
            closeNav();
        } else {
            openNav();
        }
    });

    overlay.addEventListener("click", closeNav);

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeNav();
    });

    // Close nav on resize to desktop
    window.addEventListener("resize", () => {
        if (window.innerWidth > 640) {
            closeNav();
        }
    });

    // Close nav when a nav link is clicked (mobile UX)
    nav.querySelectorAll("a").forEach(link => {
        link.addEventListener("click", () => {
            if (window.innerWidth <= 640) closeNav();
        });
    });
})();