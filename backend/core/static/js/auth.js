/**
 * CapstoneVault Authentication JavaScript
 * Full validation, fixed CSRF handling (no password toggle functionality)
 */

class AuthManager {
  constructor() {
    this.form = document.querySelector('form[method="post"]');
    this.submitBtn = document.getElementById('submitBtn');
    this.passwordField = document.getElementById('id_password');
    this.emailField = document.getElementById('id_email');
    this.csrfInput = this.form?.querySelector('input[name="csrfmiddlewaretoken"]') || null;

    this.isSubmitting = false;

    this.init();
  }

  init() {
    this.setupEventListeners();
    this.setupValidation();
    console.log('CapstoneVault Auth initialized');
  }

  setupEventListeners() {
    // Form submission
    if (this.form) {
      this.form.addEventListener('submit', (e) => this.handleFormSubmit(e));
    }

    // Real-time validation
    if (this.emailField) {
      this.emailField.addEventListener('blur', () => this.validateEmail());
      this.emailField.addEventListener('input', () => this.clearFieldError(this.emailField));
    }

    if (this.passwordField) {
      this.passwordField.addEventListener('blur', () => this.validatePassword());
      this.passwordField.addEventListener('input', () => this.clearFieldError(this.passwordField));
    }

    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.auth-alert');
    alerts.forEach(alert => {
      setTimeout(() => {
        this.hideAlert(alert);
      }, 5000);
    });
  }

  setupValidation() {
    // Add custom validation messages
    if (this.emailField) {
      this.emailField.addEventListener('invalid', (e) => {
        e.preventDefault();
        this.showFieldError(this.emailField, 'Please enter a valid email address');
      });
    }

    if (this.passwordField) {
      this.passwordField.addEventListener('invalid', (e) => {
        e.preventDefault();
        this.showFieldError(this.passwordField, 'Password is required');
      });
    }
  }

  handleFormSubmit(e) {
    if (this.isSubmitting) {
      e.preventDefault();
      return;
    }

    // Validate form before submission
    if (!this.validateForm()) {
      e.preventDefault();
      return;
    }

    this.isSubmitting = true;

    // Let the browser serialize the form (including CSRF) and start navigation,
    // then lock the UI. This avoids disabling the CSRF field before submit.
    setTimeout(() => this.showLoadingState(), 0);
  }

  validateForm() {
    let isValid = true;

    // Validate email
    if (!this.validateEmail()) {
      isValid = false;
    }

    // Validate password
    if (!this.validatePassword()) {
      isValid = false;
    }

    return isValid;
  }

  validateEmail() {
    if (!this.emailField) return true;

    const email = this.emailField.value.trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    this.clearFieldError(this.emailField);

    if (!email) {
      this.showFieldError(this.emailField, 'Email address is required');
      return false;
    }

    if (!emailRegex.test(email)) {
      this.showFieldError(this.emailField, 'Please enter a valid email address');
      return false;
    }

    return true;
  }

  validatePassword() {
    if (!this.passwordField) return true;

    const password = this.passwordField.value;

    this.clearFieldError(this.passwordField);

    if (!password) {
      this.showFieldError(this.passwordField, 'Password is required');
      return false;
    }

    if (password.length < 6) {
      this.showFieldError(this.passwordField, 'Password must be at least 6 characters');
      return false;
    }

    return true;
  }

  showFieldError(field, message) {
    // Add error border but NO validation icons
    field.classList.add('is-invalid');
    field.classList.remove('is-valid');

    // Remove existing error message
    const existingError = field.parentNode?.parentNode?.querySelector('.auth-field-error');
    if (existingError) existingError.remove();

    // Add new error message
    const errorDiv = document.createElement('div');
    errorDiv.className = 'auth-field-error';
    errorDiv.innerHTML = `<i class="bi bi-exclamation-circle me-1"></i>${message}`;

    field.parentNode?.parentNode?.appendChild(errorDiv);
  }

  clearFieldError(field) {
    field.classList.remove('is-invalid', 'is-valid');
    const errorDiv = field.parentNode?.parentNode?.querySelector('.auth-field-error');
    if (errorDiv) errorDiv.remove();
  }

  showLoadingState() {
    // Update submit button
    if (this.submitBtn) {
      const originalContent = this.submitBtn.innerHTML;
      this.submitBtn.setAttribute('data-original-content', originalContent);

      this.submitBtn.innerHTML = `
        <div class="d-flex align-items-center justify-content-center">
          <div class="spinner-border spinner-border-sm me-2" role="status">
            <span class="visually-hidden">Loading...</span>
          </div>
          Signing in...
        </div>
      `;
      this.submitBtn.disabled = true;
    }

    // Lock UI without preventing form serialization:
    // - Never disable hidden inputs (including CSRF)
    // - Keep submit button change only
    // - Make text inputs readOnly so values still submit
    const controls = this.form?.querySelectorAll('input, select, textarea, button');
    controls?.forEach(el => {
      if (el === this.submitBtn) return;

      // Never touch CSRF or any hidden fields
      if (el === this.csrfInput) return;
      if (el.type === 'hidden') return;

      // Keep values submittable
      const tag = el.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA') {
        // readOnly keeps value in POST body
        el.readOnly = true;
      } else if (tag === 'SELECT' || tag === 'BUTTON') {
        // Safe to disable post-submit
        el.disabled = true;
      } else {
        try { el.setAttribute('disabled', 'disabled'); } catch (_) {}
      }

      el.setAttribute('aria-disabled', 'true');
    });
  }

  hideAlert(alert) {
    if (!alert) return;

    alert.style.transform = 'translateX(100%)';
    alert.style.opacity = '0';

    setTimeout(() => {
      alert.remove();
    }, 300);
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.authManager = new AuthManager();
});