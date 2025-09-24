from functools import wraps
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.contrib import messages

def role_required(allowed_roles):
    """
    Require a specific role (or roles) to access a view.
    - Unauthenticated -> redirected to 'login'
    - Authenticated but wrong role -> redirected to their own dashboard (not /login/)
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required(login_url="login")
        def _wrapped(request, *args, **kwargs):
            profile = getattr(request.user, "userprofile", None)
            role = getattr(profile, "role", None)

            if role in allowed_roles:
                return view_func(request, *args, **kwargs)

            # Authenticated but wrong role -> send to their own dashboard
            try:
                from .views import redirect_dashboard_based_on_role
                messages.error(request, "Unauthorized access. Redirected to your dashboard.")
                return redirect_dashboard_based_on_role(request, role or "non_verified")
            except Exception:
                messages.error(request, "Unauthorized access.")
                return redirect("login")
        return _wrapped
    return decorator
