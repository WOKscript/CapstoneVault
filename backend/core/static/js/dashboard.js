document.addEventListener('DOMContentLoaded', function () {
  const btn = document.getElementById('sidebarToggle');
  const wrapper = document.getElementById('wrapper');
  if (!btn || !wrapper) return;

  const mqMobile = window.matchMedia('(max-width: 991.98px)');

  function toggleSidebar() {
    wrapper.classList.toggle('toggled');
    btn.setAttribute('aria-expanded', wrapper.classList.contains('toggled'));
    // Nudge charts/layout after CSS transition
    setTimeout(() => { window.dispatchEvent(new Event('resize')); }, 320);
  }

  // Primary handler (works alongside inline fallback)
  btn.addEventListener('click', toggleSidebar);

  // Entering mobile => hide overlay by default
  window.addEventListener('resize', function () {
    if (mqMobile.matches) {
      wrapper.classList.remove('toggled');
      btn.setAttribute('aria-expanded', 'false');
    }
  });

  // Close overlay when clicking outside (mobile only)
  document.addEventListener('click', function (e) {
    if (!mqMobile.matches) return;
    const sidebar = document.getElementById('sidebar-wrapper');
    const clickedToggle = e.target === btn || btn.contains(e.target);
    const clickedInside = sidebar && sidebar.contains(e.target);
    if (wrapper.classList.contains('toggled') && !clickedToggle && !clickedInside) {
      wrapper.classList.remove('toggled');
      btn.setAttribute('aria-expanded', 'false');
    }
  });
});
