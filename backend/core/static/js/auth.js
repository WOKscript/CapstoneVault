// Tiny helper to toggle password visibility
document.addEventListener('click', function (e) {
  const btn = e.target.closest('[data-toggle-pass]');
  if (!btn) return;

  const sel = btn.getAttribute('data-toggle-pass');
  const input = document.querySelector(sel);
  if (!input) return;

  const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
  input.setAttribute('type', type);

  // swap icon if using Bootstrap Icons (optional)
  const i = btn.querySelector('i');
  if (i) {
    i.classList.toggle('bi-eye');
    i.classList.toggle('bi-eye-slash');
  }
});
