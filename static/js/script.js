/**
 * Secure Login System - Frontend JavaScript
 * Handles theme toggle, toasts, form UX, password strength, and AJAX helpers.
 */

const SecureLogin = (function () {
    "use strict";

    const THEME_KEY = "secure-login-theme";

    function getCsrfToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute("content") : "";
    }

    function initThemeToggle() {
        const toggle = document.getElementById("theme-toggle");
        const icon = document.getElementById("theme-icon");
        const html = document.documentElement;
        const saved = localStorage.getItem(THEME_KEY) || "light";

        html.setAttribute("data-theme", saved);
        updateThemeIcon(icon, saved);

        if (!toggle) return;

        toggle.addEventListener("click", function () {
            const current = html.getAttribute("data-theme");
            const next = current === "dark" ? "light" : "dark";
            html.setAttribute("data-theme", next);
            localStorage.setItem(THEME_KEY, next);
            updateThemeIcon(icon, next);
        });
    }

    function updateThemeIcon(icon, theme) {
        if (!icon) return;
        icon.className = theme === "dark" ? "fas fa-sun" : "fas fa-moon";
    }

    function initFlashMessages() {
        const dataEl = document.getElementById("flash-data");
        if (!dataEl) return;

        try {
            const messages = JSON.parse(dataEl.textContent);
            messages.forEach(function (item) {
                const category = item[0] || "info";
                const message = item[1] || "";
                showToast(message, mapCategory(category));
            });
        } catch (e) {
            console.error("Failed to parse flash messages", e);
        }
    }

    function mapCategory(category) {
        const map = {
            success: "success",
            danger: "danger",
            error: "danger",
            warning: "warning",
            info: "info",
        };
        return map[category] || "info";
    }

    function showToast(message, type) {
        const container = document.getElementById("toast-container");
        if (!container) return;

        const icons = {
            success: "fa-circle-check",
            danger: "fa-circle-xmark",
            warning: "fa-triangle-exclamation",
            info: "fa-circle-info",
        };

        const toastEl = document.createElement("div");
        toastEl.className = "toast align-items-center text-bg-" + type + " border-0 show";
        toastEl.setAttribute("role", "alert");
        toastEl.setAttribute("aria-live", "assertive");
        toastEl.setAttribute("aria-atomic", "true");
        toastEl.innerHTML =
            '<div class="d-flex">' +
            '<div class="toast-body">' +
            '<i class="fas ' + (icons[type] || icons.info) + ' me-2"></i>' +
            escapeHtml(message) +
            "</div>" +
            '<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>' +
            "</div>";

        container.appendChild(toastEl);

        const toast = new bootstrap.Toast(toastEl, { delay: 5000 });
        toast.show();

        toastEl.addEventListener("hidden.bs.toast", function () {
            toastEl.remove();
        });
    }

    function escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }

    function initPasswordToggles() {
        document.querySelectorAll(".password-toggle").forEach(function (btn) {
            btn.addEventListener("click", function () {
                const targetId = btn.getAttribute("data-target");
                const input = document.getElementById(targetId);
                const icon = btn.querySelector("i");
                if (!input) return;

                if (input.type === "password") {
                    input.type = "text";
                    icon.classList.replace("fa-eye", "fa-eye-slash");
                } else {
                    input.type = "password";
                    icon.classList.replace("fa-eye-slash", "fa-eye");
                }
            });
        });
    }

    function initFormLoading() {
        document.querySelectorAll("form").forEach(function (form) {
            form.addEventListener("submit", function () {
                const overlay = document.getElementById("loading-overlay");
                const submitBtn = form.querySelector('[type="submit"]');
                if (overlay) overlay.hidden = false;
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.dataset.originalText = submitBtn.value || submitBtn.textContent;
                    if (submitBtn.tagName === "INPUT") {
                        submitBtn.value = "Please wait...";
                    } else {
                        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Please wait...';
                    }
                }
            });
        });
    }

    function initClientValidation() {
        const registerForm = document.getElementById("register-form");
        if (registerForm) {
            registerForm.addEventListener("submit", function (event) {
                const password = document.getElementById("reg-password");
                const confirm = document.getElementById("confirm-password");
                if (password && confirm && password.value !== confirm.value) {
                    event.preventDefault();
                    showToast("Passwords do not match.", "danger");
                    const overlay = document.getElementById("loading-overlay");
                    if (overlay) overlay.hidden = true;
                }
            });
        }
    }

    function initPasswordStrength(inputId, apiUrl) {
        const input = document.getElementById(inputId);
        const fill = document.getElementById("strength-fill");
        const label = document.getElementById("strength-label");
        if (!input) return;

        let debounceTimer;

        input.addEventListener("input", function () {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(function () {
                updateLocalStrength(input.value, fill, label);
                if (apiUrl && input.value.length > 0) {
                    fetchStrengthFromApi(input.value, apiUrl, fill, label);
                }
            }, 300);
        });
    }

    function updateLocalStrength(password, fill, label) {
        if (!fill) return;

        if (!password) {
            fill.style.width = "0%";
            fill.className = "strength-fill";
            if (label) label.textContent = "Password strength";
            return;
        }

        let score = 0;
        if (password.length >= 8) score += 20;
        if (password.length >= 12) score += 10;
        if (/[A-Z]/.test(password)) score += 15;
        if (/[a-z]/.test(password)) score += 15;
        if (/\d/.test(password)) score += 15;
        if (/[!@#$%^&*(),.?":{}|<>_\-\[\]\\;/+=~`']/.test(password)) score += 15;
        if (password.length >= 16) score += 10;

        score = Math.min(score, 100);
        applyStrengthUI(score, fill, label);
    }

    function fetchStrengthFromApi(password, apiUrl, fill, label) {
        fetch(apiUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": getCsrfToken(),
            },
            body: JSON.stringify({ password: password }),
        })
            .then(function (response) {
                if (!response.ok) throw new Error("API error");
                return response.json();
            })
            .then(function (data) {
                applyStrengthUI(data.score, fill, label, data.label);
            })
            .catch(function () {
                updateLocalStrength(password, fill, label);
            });
    }

    function applyStrengthUI(score, fill, label, textLabel) {
        fill.style.width = score + "%";

        let level = "weak";
        let display = textLabel || "Weak";

        if (score < 40) {
            level = "weak";
            display = textLabel || "Weak";
        } else if (score < 70) {
            level = "fair";
            display = textLabel || "Fair";
        } else if (score < 90) {
            level = "good";
            display = textLabel || "Good";
        } else {
            level = "strong";
            display = textLabel || "Strong";
        }

        fill.className = "strength-fill " + level;
        if (label) label.textContent = "Password strength: " + display;
    }

    function initPasswordRequirements(inputId) {
        const input = document.getElementById(inputId);
        const list = document.getElementById("requirements-list");
        if (!input || !list) return;

        input.addEventListener("input", function () {
            const password = input.value;
            const rules = {
                length: password.length >= 8 && password.length <= 64,
                upper: /[A-Z]/.test(password),
                lower: /[a-z]/.test(password),
                digit: /\d/.test(password),
                special: /[!@#$%^&*(),.?":{}|<>_\-\[\]\\;/+=~`']/.test(password),
            };

            list.querySelectorAll("li").forEach(function (item) {
                const rule = item.getAttribute("data-rule");
                if (rules[rule]) {
                    item.classList.add("valid");
                } else {
                    item.classList.remove("valid");
                }
            });
        });
    }

    function initOtpInput() {
        const otpInput = document.getElementById("otp-token");
        if (!otpInput) return;

        otpInput.addEventListener("input", function () {
            this.value = this.value.replace(/\D/g, "").slice(0, 6);
        });
    }

    function init() {
        initThemeToggle();
        initFlashMessages();
        initPasswordToggles();
        initFormLoading();
        initClientValidation();
        initOtpInput();
    }

    document.addEventListener("DOMContentLoaded", init);

    return {
        showToast: showToast,
        initPasswordStrength: initPasswordStrength,
        initPasswordRequirements: initPasswordRequirements,
    };
})();
