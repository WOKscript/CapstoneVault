document.addEventListener("DOMContentLoaded", () => {
  const username = document.getElementById("id_username");
  const email = document.getElementById("id_email");
  const password = document.getElementById("id_password");
  const confirmPassword = document.getElementById("id_confirm_password");

  const usernameError = document.getElementById("username-error");
  const emailError = document.getElementById("email-error");
  const passwordError = document.getElementById("password-error");
  const confirmError = document.getElementById("confirm-password-error");

  username.addEventListener("input", () => {
    const value = username.value;
    const isValid = /^[a-zA-Z0-9_]+$/.test(value);
    if (value.length < 8) {
      usernameError.textContent = "Username must be at least 8 characters.";
      username.classList.add("is-invalid");
      username.classList.remove("is-valid");
    } else if (!isValid) {
      usernameError.textContent = "Only letters, numbers, and underscores allowed.";
      username.classList.add("is-invalid");
      username.classList.remove("is-valid");
    } else {
      usernameError.textContent = "";
      username.classList.remove("is-invalid");
      username.classList.add("is-valid");
    }
  });

  email.addEventListener("input", () => {
    const value = email.value;
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(value)) {
      emailError.textContent = "Please enter a valid email address.";
      email.classList.add("is-invalid");
      email.classList.remove("is-valid");
    } else {
      emailError.textContent = "";
      email.classList.remove("is-invalid");
      email.classList.add("is-valid");
    }
  });

  password.addEventListener("input", () => {
    const value = password.value;
    const hasUpper = /[A-Z]/.test(value);
    const hasLower = /[a-z]/.test(value);
    const hasDigit = /[0-9]/.test(value);
    const hasSpecial = /[!@#$%^&*]/.test(value);

    if (value.length < 8 || !hasUpper || !hasLower || !hasDigit || !hasSpecial) {
      passwordError.textContent = "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.";
      password.classList.add("is-invalid");
      password.classList.remove("is-valid");
    } else {
      passwordError.textContent = "";
      password.classList.remove("is-invalid");
      password.classList.add("is-valid");
    }
  });

  confirmPassword.addEventListener("input", () => {
    if (confirmPassword.value !== password.value) {
      confirmError.textContent = "Passwords do not match.";
      confirmPassword.classList.add("is-invalid");
      confirmPassword.classList.remove("is-valid");
    } else {
      confirmError.textContent = "";
      confirmPassword.classList.remove("is-invalid");
      confirmPassword.classList.add("is-valid");
    }
  });
});

document.addEventListener("DOMContentLoaded", () => {
  // Username validation
  const usernameInput = document.getElementById("id_username");
  const usernameError = document.getElementById("username-error");

  usernameInput.addEventListener("input", () => {
    const value = usernameInput.value;
    const isValidChars = /^[a-zA-Z0-9_]+$/.test(value);

    if (value.length < 8) {
      usernameError.textContent = "Username must be at least 8 characters.";
      usernameInput.classList.add("is-invalid");
      usernameInput.classList.remove("is-valid");
    } else if (!isValidChars) {
      usernameError.textContent = "Username can only contain letters, numbers, and underscores.";
      usernameInput.classList.add("is-invalid");
      usernameInput.classList.remove("is-valid");
    } else {
      usernameError.textContent = "";
      usernameInput.classList.remove("is-invalid");
      usernameInput.classList.add("is-valid");
    }
  });

  // Password validation
  const passwordInput = document.getElementById("id_password");
  const passwordError = document.createElement("div");
  passwordError.className = "invalid-feedback d-block text-danger mt-1";
  passwordInput.parentNode.appendChild(passwordError);

  passwordInput.addEventListener("input", () => {
    const value = passwordInput.value;
    const rules = [
      { test: /.{8,}/, message: "At least 8 characters" },
      { test: /[A-Z]/, message: "At least one uppercase letter" },
      { test: /[a-z]/, message: "At least one lowercase letter" },
      { test: /[0-9]/, message: "At least one number" },
      { test: /[!@#$%^&*(),.?\":{}|<>]/, message: "At least one special character" },
    ];

    const failedRules = rules.filter(rule => !rule.test.test(value));

    if (failedRules.length > 0) {
      const messages = failedRules.map(r => `• ${r.message}`).join("<br>");
      passwordError.innerHTML = messages;
      passwordInput.classList.add("is-invalid");
      passwordInput.classList.remove("is-valid");
    } else {
      passwordError.innerHTML = "";
      passwordInput.classList.remove("is-invalid");
      passwordInput.classList.add("is-valid");
    }
  });
});

