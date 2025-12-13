# ============================
# core/views.py - FULL (with Adviser dropdown + Adviser Management)
# ============================

import os
import io
import joblib
import logging
import pytz
from datetime import datetime, timedelta

from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404, resolve_url
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.db.models import Count, Q
from django.http import FileResponse, Http404, JsonResponse, HttpResponse
from django.utils.text import slugify
from django.utils import timezone
from django.db.models.functions import TruncMonth
from django.views.decorators.cache import never_cache, cache_control
from django.views.decorators.csrf import csrf_protect
from django.core.paginator import Paginator

from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import Color

from pathlib import Path
from reportlab.lib.utils import ImageReader

from .models import (
    UserProfile,
    CapstonePaper,
    Category,
    SubCategory,
    Tag,
    PaperAccessRequest,
    PaperViewEvent,
    AuditLog,
    Adviser,  # ✅ NEW
)

from .forms import (
    SignupForm,
    LoginForm,
    CapstonePaperForm,
    PaperAccessRequestForm,
    AdviserForm,  # ✅ NEW
    # Profile settings forms
    UserAccountForm,
    AvatarForm,
    StyledPasswordChangeForm,
    PreferencesForm,
    SupportForm,
)

from .decorators import role_required
from .utils import create_audit_log, get_client_ip

logger = logging.getLogger(__name__)

WATERMARK_LOGO_PATH = (
    Path(settings.BASE_DIR)
    / "core"
    / "static"
    / "img"
    / "watermarks"
    / "it_logo_watermark_12pct.png"
)

# ── Load ML models ─────────────────────────────────────────────────────────────
tfidf_cat = svm_cat = tfidf_sub = svm_sub = None


def load_ml_models():
    global tfidf_cat, svm_cat, tfidf_sub, svm_sub

    if tfidf_cat is not None:
        return

    ML_DIR = os.path.join(settings.BASE_DIR, "core", "ml_models")

    try:
        tfidf_cat = joblib.load(os.path.join(ML_DIR, "tfidf_category_7th_intel_ver.pkl"))
        svm_cat = joblib.load(os.path.join(ML_DIR, "svm_category_7th_intel_ver.pkl"))
        tfidf_sub = joblib.load(os.path.join(ML_DIR, "tfidf_subcategory_7th_intel_ver.pkl"))
        svm_sub = joblib.load(os.path.join(ML_DIR, "svm_subcategory_7th_intel_ver.pkl"))
        print("ML models loaded successfully (lazy loading).")
    except Exception as e:
        print("ERROR loading ML models:", e)
        tfidf_cat = svm_cat = tfidf_sub = svm_sub = None


# ── Helpers ───────────────────────────────────────────────────────────────────
def academic_year_for(dt, start_month=8):
    """Compute AY string like '2024-2025' given a date and start month (default: Aug)."""
    y = dt.year
    return f"{y}-{y+1}" if dt.month >= start_month else f"{y-1}-{y}"


def _unique_username_from_email(email: str) -> str:
    """Create a unique, slugified username based on email's local part."""
    base = (email or "user").split("@")[0]
    base = slugify(base) or "user"
    candidate = base
    i = 1
    while User.objects.filter(username=candidate).exists():
        i += 1
        candidate = f"{base}{i}"
    return candidate


def get_role_default_dashboard(user):
    mapping = {
        "admin": "admin_dashboard",
        "instructor": "instructor_dashboard",
        "verified": "verified_dashboard",
        "non_verified": "non_verified_dashboard",
    }
    role = getattr(getattr(user, "userprofile", None), "role", None)
    return resolve_url(mapping.get(role, "verified_dashboard"))


def _user_can_upload_paper(user):
    """
    Centralized rule for showing the Upload link and allowing access
    to upload_paper_view.

    - Admin & Instructor: can always upload.
    - Verified:
        * must have can_upload == True
        * and must NOT have uploaded any paper yet
    - Non-verified: cannot upload.
    """
    profile = getattr(user, "userprofile", None)
    if not profile:
        return False

    if profile.role in ("admin", "instructor"):
        return True

    if profile.role == "verified":
        if not profile.can_upload:
            return False
        return not CapstonePaper.objects.filter(uploaded_by=user).exists()

    return False


# ── Authentication & Signup ───────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
def logout_view(request):
    logout(request)
    request.session.flush()
    resp = redirect("login")
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp["Pragma"] = "no-cache"
    resp["Expires"] = "0"
    return resp


def signup_view(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get("email", "").strip()

            if User.objects.filter(email__iexact=email).exists():
                form.add_error("email", "An account with this email already exists.")
                return render(request, "core/signup.html", {"form": form})

            user = form.save(commit=False)
            if not getattr(user, "username", None):
                user.username = _unique_username_from_email(email)

            # IMPORTANT: SignupForm here must include password in cleaned_data
            user.set_password(form.cleaned_data["password"])
            user.email = email
            user.save()

            role = "verified" if email.lower().endswith("@evsu.edu.ph") else "non_verified"
            UserProfile.objects.create(user=user, role=role)

            messages.success(request, "Signup successful! Please sign in.")
            return redirect("login")
    else:
        form = SignupForm()
    return render(request, "core/signup.html", {"form": form})


@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True, max_age=0)
@csrf_protect
def login_view(request):
    if request.user.is_authenticated:
        return redirect(get_role_default_dashboard(request.user))

    form = LoginForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = None
        try:
            u = User.objects.get(email__iexact=form.cleaned_data["email"])
            user = authenticate(request, username=u.username, password=form.cleaned_data["password"])
        except User.DoesNotExist:
            user = None

        if user:
            request.session.cycle_key()
            login(request, user)

            create_audit_log(
                user=user,
                action="user_login",
                description=f"{user.username} logged in successfully",
                ip_address=get_client_ip(request),
            )

            next_url = request.POST.get("next") or request.GET.get("next")
            if next_url:
                from django.utils.http import url_has_allowed_host_and_scheme

                if url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                    return redirect(next_url)

            return redirect(get_role_default_dashboard(user))

        form.add_error(None, "Invalid email or password.")

    return render(request, "core/login.html", {"form": form})

def redirect_dashboard_based_on_role(request, role):
    if role == 'admin':
        return redirect('admin_dashboard')
    elif role == 'instructor':
        return redirect('instructor_dashboard')
    elif role == 'verified':
        return redirect('verified_dashboard')
    elif role == 'non_verified':
        return redirect('non_verified_dashboard')
    else:
        messages.error(request, f"Unknown role: {role}. Contact admin.")
        logout(request)
        return redirect('login')

# ── Profile Settings ───────────────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def profile_settings(request):
    user = request.user
    profile = user.userprofile

    ua_form = UserAccountForm(instance=user)
    av_form = AvatarForm(instance=profile)
    pw_form = StyledPasswordChangeForm(user=user)

    if request.method == "POST":
        section = request.POST.get("section")

        if section == "account":
            ua_form = UserAccountForm(request.POST, instance=user)
            if ua_form.is_valid():
                ua_form.save()
                messages.success(request, "Account details updated.")
                return redirect("profile_settings")
            messages.error(request, "Please fix the errors in your account details.")

        elif section == "avatar":
            av_form = AvatarForm(request.POST, request.FILES, instance=profile)
            if av_form.is_valid():
                remove = av_form.cleaned_data.get("remove_avatar")
                if remove and profile.avatar:
                    profile.avatar.delete(save=False)
                    profile.avatar = None
                    profile.save(update_fields=["avatar"])
                    messages.success(request, "Avatar removed.")
                else:
                    av_form.save()
                    messages.success(request, "Avatar updated.")
                return redirect("profile_settings")
            messages.error(request, "Please fix the errors in the avatar form.")

        elif section == "password":
            pw_form = StyledPasswordChangeForm(user=user, data=request.POST)
            if pw_form.is_valid():
                user = pw_form.save()
                update_session_auth_hash(request, user)
                messages.success(request, "Password changed successfully.")
                return redirect("profile_settings")
            messages.error(request, "Please correct the errors in the password form.")

    return render(
        request,
        "core/profile_settings.html",
        {"ua_form": ua_form, "av_form": av_form, "pw_form": pw_form},
    )


# ── Dashboards ─────────────────────────────────────────────────────────────────
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def admin_dashboard(request):
    total_papers = CapstonePaper.objects.count()
    verified_users = UserProfile.objects.filter(role="verified").count()
    pending_requests = PaperAccessRequest.objects.filter(status="pending").count()
    total_logs = AuditLog.objects.count()

    return render(
        request,
        "core/dashboard_admin.html",
        {
            "total_papers": total_papers,
            "verified_users": verified_users,
            "pending_requests": pending_requests,
            "total_logs": total_logs,
        },
    )


@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["instructor"])
def instructor_dashboard(request):
    total_papers = CapstonePaper.objects.count()
    recent_papers = CapstonePaper.objects.order_by("-uploaded_at")[:5]
    return render(
        request,
        "core/dashboard_instructor.html",
        {
            "approved_count": total_papers,
            "revise_count": 0,
            "recent_papers": recent_papers,
        },
    )


@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["verified"])
def verified_dashboard(request):
    user = request.user
    can_upload = _user_can_upload_paper(user)
    has_uploaded = CapstonePaper.objects.filter(uploaded_by=user).exists()
    return render(
        request,
        "core/dashboard_verified.html",
        {"can_upload": can_upload, "has_uploaded": has_uploaded},
    )


@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["non_verified"])
def non_verified_dashboard(request):
    recent_requests = PaperAccessRequest.objects.filter(user=request.user).order_by("-requested_at")[:5]
    return render(request, "core/dashboard_non_verified.html", {"recent_requests": recent_requests})


# ── Adviser Management (Admin Only) ────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def adviser_management_view(request):
    """
    Admin page to manage Adviser names (first_name, last_name) used by CapstonePaper.adviser dropdown.
    """
    q = (request.GET.get("q") or "").strip()

    advisers = Adviser.objects.all().order_by("last_name", "first_name")
    if q:
        advisers = advisers.filter(
            Q(first_name__icontains=q) | Q(last_name__icontains=q)
        )

    if request.method == "POST":
        form = AdviserForm(request.POST)
        if form.is_valid():
            adviser = form.save()
            create_audit_log(
                user=request.user,
                action="user_updated",
                description=f"Added adviser: {adviser.first_name} {adviser.last_name}",
                ip_address=get_client_ip(request),
                metadata={"adviser_id": adviser.id},
            )
            messages.success(request, "Adviser added successfully.")
            return redirect("adviser_management")
        messages.error(request, "Please fix the errors below.")
    else:
        form = AdviserForm()

    paginator = Paginator(advisers, 20)
    page_obj = paginator.get_page(request.GET.get("page") or 1)

    return render(
        request,
        "core/adviser_management.html",
        {"form": form, "advisers": page_obj, "page_obj": page_obj, "q": q},
    )


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def adviser_edit_view(request, adviser_id):
    adviser = get_object_or_404(Adviser, id=adviser_id)

    if request.method == "POST":
        form = AdviserForm(request.POST, instance=adviser)
        if form.is_valid():
            adviser = form.save()
            create_audit_log(
                user=request.user,
                action="user_updated",
                description=f"Updated adviser: {adviser.first_name} {adviser.last_name}",
                ip_address=get_client_ip(request),
                metadata={"adviser_id": adviser.id},
            )
            messages.success(request, "Adviser updated.")
            return redirect("adviser_management")
        messages.error(request, "Please fix the errors below.")
    else:
        form = AdviserForm(instance=adviser)

    return render(request, "core/adviser_edit.html", {"form": form, "adviser": adviser})


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def adviser_delete_view(request, adviser_id):
    if request.method != "POST":
        messages.error(request, "Invalid request method.")
        return redirect("adviser_management")

    adviser = get_object_or_404(Adviser, id=adviser_id)
    name = f"{adviser.first_name} {adviser.last_name}"
    adviser.delete()

    create_audit_log(
        user=request.user,
        action="user_deleted",
        description=f"Deleted adviser: {name}",
        ip_address=get_client_ip(request),
        metadata={"adviser_name": name},
    )
    messages.success(request, "Adviser deleted.")
    return redirect("adviser_management")


# ── User Management (Admin Only) ───────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def user_management_view(request):
    search_query = request.GET.get("q", "").strip()
    role_filter = request.GET.get("role", "").strip()
    sort_by = request.GET.get("sort", "-date_joined")

    users = User.objects.select_related("userprofile").all()

    if search_query:
        users = users.filter(
            Q(username__icontains=search_query)
            | Q(email__icontains=search_query)
            | Q(first_name__icontains=search_query)
            | Q(last_name__icontains=search_query)
        )

    if role_filter:
        users = users.filter(userprofile__role=role_filter)

    valid_sorts = ["username", "-username", "email", "-email", "date_joined", "-date_joined"]
    users = users.order_by(sort_by) if sort_by in valid_sorts else users.order_by("-date_joined")

    total_users = User.objects.count()
    admin_users = UserProfile.objects.filter(role="admin").count()
    instructor_users = UserProfile.objects.filter(role="instructor").count()
    verified_users = UserProfile.objects.filter(role="verified").count()
    non_verified_users = UserProfile.objects.filter(role="non_verified").count()

    paginator = Paginator(users, 15)
    page_obj = paginator.get_page(request.GET.get("page", 1))

    return render(
        request,
        "core/user_management.html",
        {
            "users": page_obj,
            "page_obj": page_obj,
            "total_users": total_users,
            "admin_users": admin_users,
            "instructor_users": instructor_users,
            "verified_users": verified_users,
            "non_verified_users": non_verified_users,
            "search_query": search_query,
            "role_filter": role_filter,
            "sort_by": sort_by,
        },
    )


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def create_user_view(request):
    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        role = request.POST.get("role", "non_verified")
        password = request.POST.get("password", "")

        if not email:
            messages.error(request, "Email is required.")
            return redirect("user_management")

        if User.objects.filter(email__iexact=email).exists():
            messages.error(request, "A user with this email already exists.")
            return redirect("user_management")

        if not password or len(password) < 8:
            messages.error(request, "Password must be at least 8 characters.")
            return redirect("user_management")

        username = _unique_username_from_email(email)
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )

        UserProfile.objects.create(user=user, role=role)

        create_audit_log(
            user=request.user,
            action="user_created",
            description=f"Created new user: {email} with role: {role}",
            ip_address=get_client_ip(request),
            target_user=user,
            metadata={"email": email, "role": role},
        )

        messages.success(request, f"User {email} created successfully with role: {role}")
        return redirect("user_management")

    return redirect("user_management")


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def edit_user_view(request, user_id):
    user = get_object_or_404(User, id=user_id)
    profile = user.userprofile

    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        role = request.POST.get("role")
        is_active = request.POST.get("is_active") == "on"

        if user == request.user and (role != profile.role or not is_active):
            messages.error(request, "You cannot change your own role or deactivate your account.")
            return redirect("user_management")

        old_role = profile.role
        changes = []
        if old_role != role:
            changes.append(f"role changed from {old_role} to {role}")
        if user.is_active != is_active:
            changes.append(f"status changed to {'active' if is_active else 'inactive'}")

        user.email = email
        user.first_name = first_name
        user.last_name = last_name
        user.is_active = is_active
        user.save()

        profile.role = role
        profile.save()

        if changes:
            create_audit_log(
                user=request.user,
                action="user_updated",
                description=f"Updated user {user.email}: {', '.join(changes)}",
                ip_address=get_client_ip(request),
                target_user=user,
                metadata={"changes": changes, "old_role": old_role, "new_role": role},
            )

        messages.success(request, f"User {email} updated successfully.")
        return redirect("user_management")

    return redirect("user_management")


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def delete_user_view(request, user_id):
    if request.method != "POST":
        messages.error(request, "Invalid request method.")
        return redirect("user_management")

    user = get_object_or_404(User, id=user_id)

    if user == request.user:
        messages.error(request, "You cannot delete your own account.")
        return redirect("user_management")

    email = user.email
    user_role = user.userprofile.role

    create_audit_log(
        user=request.user,
        action="user_deleted",
        description=f"Deleted user: {email}",
        ip_address=get_client_ip(request),
        target_user=user,
        metadata={"email": email, "role": user_role},
    )

    user.delete()
    messages.success(request, f"User {email} has been deleted.")
    return redirect("user_management")


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def toggle_user_status(request, user_id):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid method"}, status=400)

    user = get_object_or_404(User, id=user_id)

    if user == request.user:
        return JsonResponse({"error": "Cannot deactivate your own account"}, status=400)

    user.is_active = not user.is_active
    user.save()

    return JsonResponse(
        {
            "success": True,
            "is_active": user.is_active,
            "message": f"User {'activated' if user.is_active else 'deactivated'} successfully",
        }
    )


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def reset_user_password(request, user_id):
    if request.method != "POST":
        messages.error(request, "Invalid request method.")
        return redirect("user_management")

    user = get_object_or_404(User, id=user_id)
    new_password = request.POST.get("new_password", "")

    if not new_password or len(new_password) < 8:
        messages.error(request, "Password must be at least 8 characters.")
        return redirect("user_management")

    user.set_password(new_password)
    user.save()

    create_audit_log(
        user=request.user,
        action="password_reset",
        description=f"Reset password for user: {user.email}",
        ip_address=get_client_ip(request),
        target_user=user,
    )

    messages.success(request, f"Password reset successfully for {user.email}")
    return redirect("user_management")


# ── Audit Logs (Admin Only) ────────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def audit_logs_view(request):
    search_query = request.GET.get("q", "").strip()
    action_filter = request.GET.get("action", "").strip()
    user_filter = request.GET.get("user", "").strip()
    date_from = request.GET.get("date_from", "").strip()
    date_to = request.GET.get("date_to", "").strip()

    ph_tz = pytz.timezone("Asia/Manila")

    logs = AuditLog.objects.select_related("user", "target_user").all().order_by("-created_at")

    if search_query:
        logs = logs.filter(
            Q(description__icontains=search_query)
            | Q(user__username__icontains=search_query)
            | Q(user__email__icontains=search_query)
            | Q(target_user__username__icontains=search_query)
        )

    if action_filter:
        logs = logs.filter(action=action_filter)

    if user_filter:
        logs = logs.filter(user__id=user_filter)

    if date_from:
        try:
            from_date = datetime.strptime(date_from, "%Y-%m-%d")
            from_date = ph_tz.localize(from_date)
            logs = logs.filter(created_at__gte=from_date)
        except ValueError:
            pass

    if date_to:
        try:
            to_date = datetime.strptime(date_to, "%Y-%m-%d")
            to_date = to_date.replace(hour=23, minute=59, second=59)
            to_date = ph_tz.localize(to_date)
            logs = logs.filter(created_at__lte=to_date)
        except ValueError:
            pass

    paginator = Paginator(logs, 50)
    page_obj = paginator.get_page(request.GET.get("page", 1))

    today_start = timezone.now().astimezone(ph_tz).replace(hour=0, minute=0, second=0, microsecond=0)

    context = {
        "logs": page_obj,
        "page_obj": page_obj,
        "total_logs": AuditLog.objects.count(),
        "logs_today": AuditLog.objects.filter(created_at__gte=today_start).count(),
        "unique_users_today": AuditLog.objects.filter(created_at__gte=today_start).values("user").distinct().count(),
        "action_types": AuditLog.ACTION_CHOICES,
        "users_with_logs": User.objects.filter(
            id__in=AuditLog.objects.values_list("user_id", flat=True).distinct()
        ).order_by("username"),
        "search_query": search_query,
        "action_filter": action_filter,
        "user_filter": user_filter,
        "date_from": date_from,
        "date_to": date_to,
    }

    return render(request, "core/audit_logs.html", context)


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin"])
def audit_log_detail(request, log_id):
    log = get_object_or_404(AuditLog, id=log_id)
    return render(request, "core/audit_log_detail.html", {"log": log})


# ── Machine Learning Classification ────────────────────────────────────────────
def classify_paper_ml(title, abstract):

    load_ml_models()

    if not (tfidf_cat and svm_cat and tfidf_sub and svm_sub):
        return "General", "General", []

    combined = f"{title} {abstract}".strip()

    try:
        X_cat = tfidf_cat.transform([combined])
        category = svm_cat.predict(X_cat)[0] if X_cat is not None else "General"
    except Exception:
        logger.exception("Category prediction failed")
        category = "General"

    try:
        X_sub = tfidf_sub.transform([combined])
        raw_tags = svm_sub.predict(X_sub)[0] if X_sub is not None else ""
        tags = [t.strip() for t in str(raw_tags).split(";") if t.strip()]
        subcat = tags[0] if tags else "General"
    except Exception:
        logger.exception("Subcategory/tags prediction failed")
        subcat = "General"
        tags = []

    return category, subcat, tags


# ── Upload ────────────────────────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def upload_paper_view(request):
    profile = request.user.userprofile

    if not _user_can_upload_paper(request.user):
        if profile.role == "verified":
            has_uploaded = CapstonePaper.objects.filter(uploaded_by=request.user).exists()
            if not profile.can_upload:
                messages.warning(request, "Your instructor has not granted you upload permission.")
            elif has_uploaded:
                messages.warning(request, "You are allowed to upload only one capstone paper.")
            else:
                messages.warning(request, "You are not allowed to upload capstone papers.")
            return redirect("verified_dashboard")

        if profile.role == "non_verified":
            messages.error(request, "Non-verified users cannot upload capstone papers.")
            return redirect("non_verified_dashboard")

        messages.error(request, "You are not allowed to upload capstone papers.")
        return redirect(get_role_default_dashboard(request.user))

    if request.method == "POST":
        form = CapstonePaperForm(request.POST, request.FILES)
        if form.is_valid():
            paper = form.save(commit=False)
            paper.uploaded_by = request.user

            # ✅ ML classification (will now work because load_ml_models() is called inside classify_paper_ml)
            cat_name, sub_name, tag_list = classify_paper_ml(
                form.cleaned_data["title"],
                form.cleaned_data["abstract"],
            )

            cat_obj, _ = Category.objects.get_or_create(name=cat_name)
            sub_obj, _ = SubCategory.objects.get_or_create(name=sub_name, category=cat_obj)
            paper.category = cat_obj
            paper.subcategory = sub_obj

            paper.save()

            for name in tag_list:
                tag_obj, _ = Tag.objects.get_or_create(name=name)
                paper.tags.add(tag_obj)

            create_audit_log(
                user=request.user,
                action="paper_uploaded",
                description=f"Uploaded paper: {paper.title}",
                ip_address=get_client_ip(request),
                metadata={"paper_id": paper.id, "ml_category": cat_name, "ml_subcategory": sub_name, "ml_tags": tag_list},
            )

            messages.success(request, "Capstone paper uploaded and classified successfully!")

            if profile.role == "admin":
                return redirect("admin_dashboard")
            if profile.role == "instructor":
                return redirect("instructor_dashboard")
            if profile.role == "verified":
                return redirect("verified_dashboard")
            return redirect("capstones_main")

        messages.error(request, "Failed to upload paper. Please check the form.")
    else:
        form = CapstonePaperForm()

    can_upload = _user_can_upload_paper(request.user)

    return render(
        request,
        "core/upload_paper.html",
        {"form": form, "can_upload": can_upload},
    )

# ── Search ────────────────────────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def search_results_view(request):
    q = (request.GET.get("q") or "").strip()

    if not q:
        return render(request, "core/search_results.html", {"papers": [], "query": q, "count": 0})

    papers = (
        CapstonePaper.objects.filter(
            Q(title__icontains=q)
            | Q(abstract__icontains=q)
            | Q(authors__icontains=q)
            | Q(adviser__first_name__icontains=q)
            | Q(adviser__last_name__icontains=q)
            | Q(category__name__icontains=q)
            | Q(subcategory__name__icontains=q)
            | Q(tags__name__icontains=q)
        )
        .distinct()
        .order_by("-publication_year", "title")
    )

    return render(
        request,
        "core/search_results.html",
        {"papers": papers, "query": q, "count": papers.count()},
    )


# ── Capstones Main ────────────────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def capstones_main_view(request):
    q = (request.GET.get("q") or "").strip()
    sort = (request.GET.get("sort") or "").strip()

    categories = Category.objects.all()

    if q:
        cat_matches = categories.filter(name__icontains=q).annotate(paper_count=Count("capstonepaper"))
        if not cat_matches.exists():
            return redirect(f"/search/?q={q}")
        categories = cat_matches
    else:
        categories = categories.annotate(paper_count=Count("capstonepaper"))

    categories = categories.order_by("-paper_count", "name") if sort == "count" else categories.order_by("name")

    can_upload = _user_can_upload_paper(request.user)

    return render(request, "core/capstones.html", {"categories": categories, "can_upload": can_upload})


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def capstone_list_by_category(request, category):
    cat = get_object_or_404(Category, slug=category)

    q = (request.GET.get("q") or "").strip()
    year = (request.GET.get("year") or "").strip()
    subcat = (request.GET.get("subcategory") or "").strip()
    sort = (request.GET.get("sort") or "").strip()

    qs = CapstonePaper.objects.filter(category=cat)

    if year.isdigit():
        qs = qs.filter(publication_year=int(year))
    if subcat:
        qs = qs.filter(subcategory__name__iexact=subcat)

    if q:
        ft = (
            Q(title__icontains=q)
            | Q(abstract__icontains=q)
            | Q(authors__icontains=q)
            | Q(adviser__first_name__icontains=q)
            | Q(adviser__last_name__icontains=q)
            | Q(category__name__icontains=q)
            | Q(subcategory__name__icontains=q)
            | Q(tags__name__icontains=q)
        )
        if q.isdigit():
            ft |= Q(publication_year=int(q))
        qs = qs.filter(ft).distinct()

    if sort == "year_asc":
        qs = qs.order_by("publication_year", "title")
    elif sort == "title_asc":
        qs = qs.order_by("title")
    else:
        qs = qs.order_by("-publication_year", "title")

    years = (
        CapstonePaper.objects.filter(category=cat)
        .values_list("publication_year", flat=True)
        .distinct()
        .order_by("-publication_year")
    )
    subcategories = (
        SubCategory.objects.filter(category=cat)
        .values_list("name", flat=True)
        .distinct()
    )

    role = getattr(getattr(request.user, "userprofile", None), "role", "non_verified")
    approved_ids = []
    if role == "non_verified":
        approved_ids = PaperAccessRequest.objects.filter(
            user=request.user,
            status="approved",
            expires_at__gte=timezone.now(),
        ).values_list("paper_id", flat=True)

    can_upload = _user_can_upload_paper(request.user)

    return render(
        request,
        "core/capstone_list.html",
        {
            "category": cat,
            "papers": qs,
            "search_query": q,
            "selected_year": year,
            "years": years,
            "selected_subcategory": subcat,
            "subcategories": subcategories,
            "approved_access_ids": list(approved_ids),
            "can_upload": can_upload,
        },
    )


# ── Edit / Delete ─────────────────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def edit_paper_view(request, paper_id):
    paper = get_object_or_404(CapstonePaper, id=paper_id)

    role = getattr(getattr(request.user, "userprofile", None), "role", "non_verified")
    is_admin_or_instr = role in ["admin", "instructor"]
    is_verified_owner = role == "verified" and paper.uploaded_by == request.user

    if not (is_admin_or_instr or is_verified_owner):
        messages.error(request, "You don't have permission to edit this paper.")
        return redirect("capstones_by_category", category=paper.category.slug)

    if request.method == "POST":
        form = CapstonePaperForm(request.POST, request.FILES, instance=paper)
        if form.is_valid():
            paper = form.save(commit=False)

            cat_name, sub_name, tag_list = classify_paper_ml(
                form.cleaned_data["title"],
                form.cleaned_data["abstract"],
            )
            paper.category, _ = Category.objects.get_or_create(name=cat_name)
            paper.subcategory, _ = SubCategory.objects.get_or_create(name=sub_name, category=paper.category)
            paper.save()

            paper.tags.clear()
            for name in tag_list:
                tag_obj, _ = Tag.objects.get_or_create(name=name)
                paper.tags.add(tag_obj)

            create_audit_log(
                user=request.user,
                action="paper_edited",
                description=f"Edited paper: {paper.title}",
                ip_address=get_client_ip(request),
                metadata={"paper_id": paper.id},
            )

            messages.success(request, "Capstone paper updated successfully.")
            if is_admin_or_instr:
                return redirect("capstones_by_category", category=paper.category.slug)
            return redirect("verified_dashboard")
    else:
        form = CapstonePaperForm(instance=paper)

    return render(request, "core/edit_paper.html", {"form": form, "paper": paper})


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def delete_paper_view(request, paper_id):
    paper = get_object_or_404(CapstonePaper, id=paper_id)
    role = getattr(getattr(request.user, "userprofile", None), "role", "non_verified")

    is_admin_or_instr = role in ["admin", "instructor"]
    is_verified_owner = role == "verified" and paper.uploaded_by == request.user

    if not (is_admin_or_instr or is_verified_owner):
        messages.error(request, "You don't have permission to delete this paper.")
        return redirect("capstones_by_category", category=paper.category.slug)

    if request.method == "POST":
        category = paper.category
        subcategory = paper.subcategory
        cat_slug = category.slug if category else None

        has_other_in_cat = bool(category and CapstonePaper.objects.filter(category=category).exclude(id=paper.id).exists())
        has_other_in_sub = bool(subcategory and CapstonePaper.objects.filter(subcategory=subcategory).exclude(id=paper.id).exists())

        title = paper.title
        paper.delete()

        if category and not has_other_in_cat:
            category.delete()
        if subcategory and not has_other_in_sub:
            subcategory.delete()

        create_audit_log(
            user=request.user,
            action="paper_deleted",
            description=f"Deleted paper: {title}",
            ip_address=get_client_ip(request),
            metadata={"paper_title": title},
        )

        messages.success(request, f"\"{title}\" was deleted successfully.")

        if cat_slug and has_other_in_cat and Category.objects.filter(slug=cat_slug).exists():
            return redirect("capstones_by_category", category=cat_slug)
        return redirect("capstones_main")

    messages.info(request, "Deletion must be confirmed via the modal.")
    return redirect("capstones_by_category", category=paper.category.slug)


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def cancel_revision(request, paper_id):
    if request.method != "POST":
        messages.error(request, "Invalid request method.")
        return redirect("verified_dashboard")

    paper = get_object_or_404(CapstonePaper, id=paper_id)

    if paper.uploaded_by != request.user:
        messages.error(request, "You can only cancel your own paper.")
        return redirect("verified_dashboard")

    title = paper.title
    paper.delete()
    messages.success(request, f"'{title}' has been removed.")
    return redirect("verified_dashboard")


# ── Upload Access Management ───────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["instructor"])
def manage_upload_access(request):
    users = UserProfile.objects.filter(role="verified")
    return render(request, "core/manage_upload_access.html", {"users": users})


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["instructor"])
def toggle_upload_access(request, user_id):
    profile = get_object_or_404(UserProfile, user__id=user_id, role="verified")
    profile.can_upload = not profile.can_upload
    profile.save()
    msg = "granted" if profile.can_upload else "revoked"

    create_audit_log(
        user=request.user,
        action="upload_permission_changed",
        description=f"{profile.user.username}: upload {msg}.",
        ip_address=get_client_ip(request),
        target_user=profile.user,
        metadata={"can_upload": profile.can_upload},
    )

    messages.success(request, f"{profile.user.username}: upload {msg}.")
    return redirect("manage_upload_access")


# ── Paper Access Requests ──────────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def request_access_view(request, paper_id):
    paper = get_object_or_404(CapstonePaper, id=paper_id)
    profile = request.user.userprofile

    if profile.role in ["admin", "instructor", "verified"]:
        messages.info(request, "You can view this paper directly.")
        return redirect("view_paper", paper_id=paper.id)

    if request.method == "POST":
        form = PaperAccessRequestForm(request.POST)
        if form.is_valid():
            req = form.save(commit=False)
            req.user = request.user
            req.paper = paper
            req.status = "pending"
            req.save()
            messages.success(request, "Access request submitted!")
            return redirect("capstones_main")
    else:
        form = PaperAccessRequestForm()

    return render(request, "core/request_access.html", {"form": form, "paper": paper})


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin", "instructor"])
def access_request_list(request):
    q = (request.GET.get("q") or "").strip()
    status_f = (request.GET.get("status") or "").strip()

    qs = PaperAccessRequest.objects.select_related("user", "paper").order_by("-requested_at")

    if q:
        qs = qs.filter(
            Q(user__username__icontains=q)
            | Q(user__email__icontains=q)
            | Q(paper__title__icontains=q)
            | Q(reason__icontains=q)
        )

    if status_f in ("pending", "approved", "rejected"):
        qs = qs.filter(status=status_f)

    counts = {
        "total": PaperAccessRequest.objects.count(),
        "pending": PaperAccessRequest.objects.filter(status="pending").count(),
        "approved": PaperAccessRequest.objects.filter(status="approved").count(),
        "rejected": PaperAccessRequest.objects.filter(status="rejected").count(),
    }

    paginator = Paginator(qs, 15)
    page_obj = paginator.get_page(request.GET.get("page") or 1)

    return render(
        request,
        "core/access_request_list.html",
        {"requests": page_obj, "page_obj": page_obj, "counts": counts, "q": q, "status_f": status_f},
    )


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin", "instructor"])
def approve_access_request(request, request_id):
    req = get_object_or_404(PaperAccessRequest, id=request_id)

    try:
        days = int(request.POST.get("days") or request.GET.get("days") or 7)
    except ValueError:
        days = 7
    days = max(1, min(days, 365))

    now = timezone.now()
    req.status = "approved"
    req.approved_at = now
    req.expires_at = now + timedelta(days=days)
    req.save()

    create_audit_log(
        user=request.user,
        action="access_granted",
        description=f"Granted access to {req.user.username} for '{req.paper.title}' ({days} days)",
        ip_address=get_client_ip(request),
        target_user=req.user,
        metadata={"paper_id": req.paper_id, "days": days, "expires_at": req.expires_at.isoformat()},
    )

    messages.success(
        request,
        f"Approved for {req.user.username} — expires {req.expires_at.strftime('%b %d, %Y %I:%M %p')}",
    )
    return redirect("access_request_list")


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(["admin", "instructor"])
def reject_access_request(request, request_id):
    req = get_object_or_404(PaperAccessRequest, id=request_id)
    req.status = "rejected"
    req.save()

    create_audit_log(
        user=request.user,
        action="access_denied",
        description=f"Rejected access for '{req.paper.title}' by {req.user.username}",
        ip_address=get_client_ip(request),
        target_user=req.user,
        metadata={"paper_id": req.paper_id},
    )

    messages.error(request, f"Rejected access for '{req.paper.title}' by {req.user.username}")
    return redirect("access_request_list")


# ── Watermarked PDF Helper Functions ───────────────────────────────────────────

def _build_logo_watermark_page(page_w: float, page_h: float, logo_path: Path):
    """
    Builds a single-page PDF watermark containing the logo.
    The PNG should already have reduced opacity (alpha) so it renders faint.
    """
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(page_w, page_h))

    img = ImageReader(str(logo_path))
    iw, ih = img.getSize()

    # Scale logo to fit ~55% of page size (adjust if needed)
    max_w = page_w * 0.55
    max_h = page_h * 0.55
    scale_factor = min(max_w / float(iw), max_h / float(ih))

    target_w = float(iw) * scale_factor
    target_h = float(ih) * scale_factor

    x = (page_w - target_w) / 2.0
    y = (page_h - target_h) / 2.0

    # mask='auto' keeps PNG transparency
    c.drawImage(img, x, y, width=target_w, height=target_h, mask="auto")

    c.showPage()
    c.save()
    buf.seek(0)
    return PdfReader(buf).pages[0]

def _add_watermark_to_pdf_filelike(fileobj, watermark_text: str) -> io.BytesIO:
    """
    Applies watermark to PDF.
    - Preferred: centered LOGO watermark (PNG with transparency/low opacity)
    - Fallback: diagonal TEXT watermark (existing behavior)
    """
    logger.info(f"Starting watermark process: '{watermark_text}'")

    try:
        data = fileobj.read()
        if not data:
            raise ValueError("Empty PDF file")

        src = io.BytesIO(data)
        reader = PdfReader(src)
        writer = PdfWriter()

        if getattr(reader, "is_encrypted", False):
            try:
                reader.decrypt("")
            except Exception as e:
                logger.error(f"Failed to decrypt PDF: {e}")
                fileobj.seek(0)
                return io.BytesIO(fileobj.read())

        # ✅ Try logo watermark first (requires WATERMARK_LOGO_PATH + ImageReader imports)
        try:
            logo_exists = WATERMARK_LOGO_PATH.exists()
        except Exception:
            logo_exists = False

        wm_cache = {}  # cache by (w,h) so we don't rebuild per page

        for page in reader.pages:
            try:
                mb = page.mediabox
                w, h = float(mb.width), float(mb.height)
            except Exception:
                w, h = 612.0, 792.0

            wm_page = None

            # ── Preferred: logo watermark ─────────────────────────────
            if logo_exists:
                key = (w, h)
                if key not in wm_cache:
                    wm_cache[key] = _build_logo_watermark_page(w, h, WATERMARK_LOGO_PATH)
                wm_page = wm_cache[key]

            # ── Fallback: text watermark (your original code) ─────────
            if wm_page is None:
                buf = io.BytesIO()
                c = canvas.Canvas(buf, pagesize=(w, h))

                diag = (w**2 + h**2) ** 0.5
                font_name = "Helvetica-Bold"
                font_size = max(48, int(diag * 0.12))

                try:
                    c.setFillColor(Color(0.2, 0.2, 0.2, alpha=0.18))
                except Exception:
                    c.setFillColorRGB(0.8, 0.8, 0.8)

                if hasattr(c, "setFillAlpha"):
                    try:
                        c.setFillAlpha(0.18)
                    except Exception:
                        pass

                c.setFont(font_name, font_size)

                text_w = c.stringWidth(watermark_text, font_name, font_size)
                c.saveState()
                c.translate(w / 2.0, h / 2.0)
                c.rotate(45)
                c.drawString(-text_w / 2.0, -font_size * 0.35, watermark_text)
                c.restoreState()

                c.showPage()
                c.save()

                buf.seek(0)
                wm_reader = PdfReader(buf)
                wm_page = wm_reader.pages[0]

            # ── Merge watermark ───────────────────────────────────────
            if hasattr(page, "merge_page"):
                page.merge_page(wm_page)
            elif hasattr(page, "mergePage"):
                page.mergePage(wm_page)
            else:
                page.mergeTransformedPage(wm_page, [1, 0, 0, 1, 0, 0])

            writer.add_page(page)

        out = io.BytesIO()
        writer.write(out)
        out.seek(0)
        return out

    except Exception as e:
        logger.error(f"Watermarking failed: {e}")
        try:
            fileobj.seek(0)
            return io.BytesIO(fileobj.read())
        except Exception:
            raise Http404("Could not process PDF file")



# ── Secure PDF Viewing ─────────────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def view_paper(request, paper_id):
    paper = get_object_or_404(CapstonePaper, id=paper_id)

    role = getattr(getattr(request.user, "userprofile", None), "role", "non_verified")
    is_admin_or_instr = role in ["admin", "instructor"]
    is_uploader = paper.uploaded_by_id == request.user.id
    is_verified = role == "verified"

    if not (is_admin_or_instr or is_uploader):
        if not is_verified:
            has_access = PaperAccessRequest.objects.filter(
                user=request.user,
                paper=paper,
                status="approved",
                expires_at__gte=timezone.now(),
            ).exists()
            if not has_access:
                messages.error(request, "You don't have access to view this paper.")
                return redirect("capstones_by_category", category=paper.category.slug)

    now = timezone.localtime()
    ay = academic_year_for(now, start_month=8)
    PaperViewEvent.objects.create(paper=paper, user=request.user, ay=ay)

    return render(
        request,
        "core/secure_pdf_viewer.html",
        {
            "paper": paper,
            "paper_id": paper_id,
            "user": request.user,
            "user_name": request.user.get_full_name() or request.user.username,
        },
    )


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def serve_secure_pdf(request, paper_id):
    logger.info(f"Serving PDF for paper {paper_id} to user {request.user.id}")

    paper = get_object_or_404(CapstonePaper, id=paper_id)

    role = getattr(getattr(request.user, "userprofile", None), "role", "non_verified")
    is_admin_or_instr = role in ["admin", "instructor"]
    is_uploader = paper.uploaded_by_id == request.user.id
    is_verified = role == "verified"

    if not (is_admin_or_instr or is_uploader):
        if not is_verified:
            has_access = PaperAccessRequest.objects.filter(
                user=request.user,
                paper=paper,
                status="approved",
                expires_at__gte=timezone.now(),
            ).exists()
            if not has_access:
                raise Http404("Access denied")

    file_field = getattr(paper, "file", None)
    if not file_field or not getattr(file_field, "name", ""):
        raise Http404("PDF not found")

    safe_name = slugify(paper.title) or f"paper-{paper.id}"
    filename = f"{safe_name}.pdf"

    def _make_response(filelike):
        resp = FileResponse(filelike, as_attachment=False, filename=filename, content_type="application/pdf")
        resp["Content-Disposition"] = f'inline; filename="{filename}"'
        resp["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
        resp["Pragma"] = "no-cache"
        resp["Expires"] = "0"
        resp["X-Frame-Options"] = "SAMEORIGIN"
        resp["X-Content-Type-Options"] = "nosniff"
        resp["Content-Security-Policy"] = "frame-ancestors 'self'"
        resp["Referrer-Policy"] = "same-origin"
        resp["Permissions-Policy"] = "clipboard-read=(), clipboard-write=()"
        return resp

    if request.GET.get("raw") == "1":
        try:
            return _make_response(file_field.open("rb"))
        except Exception:
            raise Http404("Could not stream original PDF")

    try:
        with file_field.open("rb") as f:
            watermarked_pdf = _add_watermark_to_pdf_filelike(f, "EVSU-IT")
            return _make_response(watermarked_pdf)
    except Exception:
        try:
            return _make_response(file_field.open("rb"))
        except Exception:
            raise Http404("There was a problem preparing the PDF")


@login_required
def debug_watermark_test(request, paper_id):
    paper = get_object_or_404(CapstonePaper, id=paper_id)

    try:
        with paper.file.open("rb") as f:
            original_size = len(f.read())
            f.seek(0)
            watermarked = _add_watermark_to_pdf_filelike(f, "DEBUG TEST")
            watermarked_size = len(watermarked.getvalue())

        return HttpResponse(
            f"""
        <html><head><title>Watermark Debug</title></head>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>Watermark Test Results</h2>
            <p><strong>Paper:</strong> {paper.title}</p>
            <p><strong>Original PDF size:</strong> {original_size:,} bytes</p>
            <p><strong>Watermarked PDF size:</strong> {watermarked_size:,} bytes</p>
            <p><strong>Status:</strong> {'✓ SUCCESS' if watermarked_size > 0 else '❌ FAILED'}</p>
            <hr>
            <p><a href="/papers/{paper_id}/pdf/?raw=1" target="_blank">View Original PDF</a></p>
            <p><a href="/papers/{paper_id}/pdf/" target="_blank">View Watermarked PDF</a></p>
            <p><a href="/papers/{paper_id}/view/" target="_blank">View in PDF Viewer</a></p>
        </body></html>
        """,
            content_type="text/html",
        )
    except Exception as e:
        return HttpResponse(
            f"""
        <html><head><title>Watermark Debug - Error</title></head>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>❌ Watermark Test Error</h2>
            <p><strong>Error:</strong> {e}</p>
            <p><a href="javascript:history.back()">← Go Back</a></p>
        </body></html>
        """,
            content_type="text/html",
        )


# ── Trends ────────────────────────────────────────────────────────────────────
def _trends_qs():
    return CapstonePaper.objects.exclude(publication_year__isnull=True)


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def trends_dashboard(request):
    return render(request, "core/trends.html")


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def trends_api(request):
    qs = _trends_qs()

    yearly = qs.values("publication_year").annotate(count=Count("id")).order_by("publication_year")
    years = [str(r["publication_year"]) for r in yearly]
    counts = [r["count"] for r in yearly]

    by_cat_year = (
        qs.values("publication_year", "category__name")
        .annotate(count=Count("id"))
        .order_by("publication_year", "category__name")
    )
    categories = sorted({r["category__name"] or "Uncategorized" for r in by_cat_year})
    idx_map = {y: i for i, y in enumerate(years)}
    cat_series = {c: [0] * len(years) for c in categories}
    for r in by_cat_year:
        c = r["category__name"] or "Uncategorized"
        y = str(r["publication_year"])
        if y in idx_map:
            cat_series[c][idx_map[y]] = r["count"]

    return JsonResponse(
        {
            "yearly": {"labels": years, "counts": counts},
            "stackedByCategory": {
                "labels": years,
                "series": [{"name": c, "data": cat_series[c]} for c in categories],
            },
        }
    )


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def most_accessed_api(request):
    ay = request.GET.get("ay")
    if not ay:
        ay = academic_year_for(timezone.localtime(), start_month=8)

    top_qs = (
        PaperViewEvent.objects.filter(ay=ay)
        .values("paper_id", "paper__title", "paper__authors")
        .annotate(views=Count("id"))
        .order_by("-views")[:10]
    )

    monthly = (
        PaperViewEvent.objects.filter(ay=ay)
        .annotate(m=TruncMonth("viewed_at"))
        .values("m")
        .annotate(views=Count("id"))
        .order_by("m")
    )

    return JsonResponse(
        {
            "ay": ay,
            "topPapers": [
                {"paperId": r["paper_id"], "title": r["paper__title"], "authors": r["paper__authors"], "views": r["views"]}
                for r in top_qs
            ],
            "monthly": {
                "labels": [d["m"].strftime("%b %Y") for d in monthly],
                "views": [d["views"] for d in monthly],
            },
        }
    )


# ── Preferences & Help ─────────────────────────────────────────────────────────
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def preferences_view(request):
    prefs = request.session.get("user_prefs", {})
    if request.method == "POST":
        form = PreferencesForm(request.POST, initial=prefs)
        if form.is_valid():
            request.session["user_prefs"] = form.cleaned_data
            messages.success(request, "Preferences saved.")
            return redirect("preferences")
        messages.error(request, "Please fix the errors below.")
    else:
        form = PreferencesForm(initial=prefs)

    return render(request, "core/preferences.html", {"form": form})


@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def help_support_view(request):
    if request.method == "POST":
        form = SupportForm(request.POST)
        if form.is_valid():
            payload = {
                "subject": form.cleaned_data["subject"],
                "message": form.cleaned_data["message"],
                "page": form.cleaned_data.get("page") or "",
                "agent": request.META.get("HTTP_USER_AGENT", ""),
            }

            # NOTE: make sure your AuditLog.ACTION_CHOICES includes "support_request" if you keep this
            create_audit_log(
                user=request.user,
                action="support_request",
                description=f"Support: {payload['subject']}",
                ip_address=get_client_ip(request),
                metadata=payload,
            )

            messages.success(request, "Thanks! Your request has been recorded. We’ll get back to you.")
            return redirect("help_support")
        messages.error(request, "Please fix the errors below.")
    else:
        form = SupportForm()

    faqs = [
        {
            "q": "How do I change my password?",
            "a": "Go to Profile Settings → Security, fill out the password form, and click Update Password.",
        },
        {
            "q": "Where can I upload my capstone?",
            "a": "If you’re verified and your instructor enabled uploads, go to Capstones → Upload PDF.",
        },
        {
            "q": "Why can’t I view a full paper?",
            "a": "If you are not admin/instructor/uploader, you’ll need an approved access request that hasn’t expired.",
        },
    ]
    return render(request, "core/help_support.html", {"form": form, "faqs": faqs})
