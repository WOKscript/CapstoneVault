# ============================
# core/views.py
# ============================
import os
import io
import joblib
from datetime import datetime

from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404, resolve_url
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import Count, Q
from django import forms
from django.http import FileResponse, Http404, JsonResponse
from django.utils.text import slugify
from django.utils import timezone
from django.db.models.functions import TruncMonth

from django.views.decorators.cache import never_cache, cache_control
from django.views.decorators.csrf import csrf_protect

from .models import (
    UserProfile,
    CapstonePaper,
    Category,
    SubCategory,
    Tag,
    PaperAccessRequest,
    PaperViewEvent,
)
from .forms import (
    SignupForm,
    LoginForm,
    CapstonePaperForm,
    PaperAccessRequestForm,
)
from .decorators import role_required

# --- PDF watermarking deps ---
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import Color

# ── Load ML models ─────────────────────────────────────────────────────────────
BASE_DIR = settings.BASE_DIR
ML_DIR = os.path.join(BASE_DIR, 'core', 'ml_models')
tfidf_cat = joblib.load(os.path.join(ML_DIR, 'tfidf_category_2nd_ver.pkl'))
svm_cat = joblib.load(os.path.join(ML_DIR, 'svm_category_2nd_ver.pkl'))
tfidf_sub = joblib.load(os.path.join(ML_DIR, 'tfidf_subcategory_2nd_ver.pkl'))
svm_sub = joblib.load(os.path.join(ML_DIR, 'svm_subcategory_2nd_ver.pkl'))

# ── Helpers ───────────────────────────────────────────────────────────────────
def academic_year_for(dt, start_month=8):
    """Compute AY string like '2024-2025' given a date and start month (default: Aug)."""
    y = dt.year
    if dt.month >= start_month:
        return f"{y}-{y+1}"
    return f"{y-1}-{y}"

def _unique_username_from_email(email: str) -> str:
    """
    Create a unique, slugified username based on email's local part.
    Keeps default User model happy even if you log in via email.
    """
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

# ── Authentication & Signup ───────────────────────────────────────────────────

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
def logout_view(request):
    logout(request)
    request.session.flush()
    resp = redirect('login')
    resp['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp['Pragma'] = 'no-cache'
    resp['Expires'] = '0'
    return resp


def signup_view(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email', '').strip()

            if User.objects.filter(email__iexact=email).exists():
                form.add_error('email', 'An account with this email already exists.')
                return render(request, 'core/signup.html', {'form': form})

            user = form.save(commit=False)

            if not getattr(user, 'username', None):
                user.username = _unique_username_from_email(email)

            user.set_password(form.cleaned_data['password'])
            user.email = email
            user.save()

            role = 'verified' if email.lower().endswith('@evsu.edu.ph') else 'non_verified'
            UserProfile.objects.create(user=user, role=role)

            messages.success(request, "Signup successful! Please sign in.")
            return redirect('login')
    else:
        form = SignupForm()
    return render(request, 'core/signup.html', {'form': form})

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True, max_age=0)
@csrf_protect
def login_view(request):
    # If already authenticated, go straight to your dashboard
    if request.user.is_authenticated:
        return redirect(get_role_default_dashboard(request.user))

    form = LoginForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        # If you authenticate by email, resolve to username first
        user = None
        try:
            u = User.objects.get(email__iexact=form.cleaned_data['email'])
            user = authenticate(request, username=u.username, password=form.cleaned_data['password'])
        except User.DoesNotExist:
            user = None

        if user:
            request.session.cycle_key()
            login(request, user)

            # Honor ?next= if it's safe
            next_url = request.POST.get("next") or request.GET.get("next")
            if next_url:
                from django.utils.http import url_has_allowed_host_and_scheme
                if url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                    return redirect(next_url)

            return redirect(get_role_default_dashboard(user))

        form.add_error(None, "Invalid email or password.")

    return render(request, 'core/login.html', {'form': form})

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

# ── Dashboards ─────────────────────────────────────────────────────────────────

@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['admin'])
def admin_dashboard(request):
    total_papers     = CapstonePaper.objects.count()
    verified_users   = UserProfile.objects.filter(role='verified').count()
    pending_requests = PaperAccessRequest.objects.filter(status='pending').count()
    session_logs     = 0

    context = {
        'total_papers': total_papers,
        'verified_users': verified_users,
        'pending_requests': pending_requests,
        'session_logs': session_logs,
    }
    return render(request, 'core/dashboard_admin.html', context)


@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['instructor'])
def instructor_dashboard(request):
    """
    No more 'status' field – show totals and recent items.
    """
    total_papers  = CapstonePaper.objects.count()
    recent_papers = CapstonePaper.objects.order_by('-uploaded_at')[:5]

    # Keep template keys so existing template won't crash.
    context = {
        'approved_count': total_papers,  # formerly 'approved'
        'revise_count': 0,               # no 'revise' anymore
        'recent_papers': recent_papers,
    }
    return render(request, 'core/dashboard_instructor.html', context)

@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['verified'])
def verified_dashboard(request):
    user = request.user

    can_upload      = bool(getattr(user.userprofile, 'can_upload', False))

    context = {
        'can_upload': can_upload,
    }
    return render(request, 'core/dashboard_verified.html', context)

@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['non_verified'])
def non_verified_dashboard(request):
    recent_requests = PaperAccessRequest.objects.filter(user=request.user).order_by('-requested_at')[:5]
    return render(request, 'core/dashboard_non_verified.html', {'recent_requests': recent_requests})

# ── Machine Learning Classification ────────────────────────────────────────────

def classify_paper_ml(title, abstract):
    combined = title + ' ' + abstract
    X_cat    = tfidf_cat.transform([combined])
    category = svm_cat.predict(X_cat)[0] if X_cat is not None else 'General'

    X_sub     = tfidf_sub.transform([combined])
    raw_tags  = svm_sub.predict(X_sub)[0] if X_sub is not None else ''
    tags      = [t.strip() for t in raw_tags.split(';') if t.strip()]
    subcat    = tags[0] if tags else 'General'

    return category, subcat, tags

# ── Upload & Listing ───────────────────────────────────────────────────────────

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def upload_paper_view(request):
    profile = request.user.userprofile

    if profile.role == 'verified' and not profile.can_upload:
        messages.warning(request, "Your instructor has not granted you upload permission.")
        return redirect('verified_dashboard')

    if request.method == 'POST':
        form = CapstonePaperForm(request.POST, request.FILES)
        if form.is_valid():
            paper = form.save(commit=False)
            paper.uploaded_by = request.user

            cat_name, sub_name, tag_list = classify_paper_ml(
                form.cleaned_data['title'],
                form.cleaned_data['abstract']
            )
            cat_obj, _ = Category.objects.get_or_create(name=cat_name)
            sub_obj, _ = SubCategory.objects.get_or_create(name=sub_name, category=cat_obj)
            paper.category = cat_obj
            paper.subcategory = sub_obj

            paper.save()

            for name in tag_list:
                tag_obj, _ = Tag.objects.get_or_create(name=name)
                paper.tags.add(tag_obj)

            messages.success(request, 'Capstone paper uploaded and classified successfully!')
            return redirect('admin_dashboard' if profile.role == 'admin' else 'verified_dashboard')
        else:
            messages.error(request, 'Failed to upload paper. Please check the form.')
    else:
        form = CapstonePaperForm()

    can_upload = (profile.role == 'verified' and profile.can_upload)

    return render(request, 'core/upload_paper.html', {
        'form': form,
        'can_upload': can_upload,
    })

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def capstones_main_view(request):
    """
    Categories page with:
      - search by category name (?q=)
      - sort by name or paper count (?sort=name|count)
      - paper_count counts ALL papers (no status anymore)
    """
    q = (request.GET.get("q") or "").strip()
    sort = (request.GET.get("sort") or "").strip()

    categories = Category.objects.annotate(paper_count=Count("capstonepaper"))

    if q:
        categories = categories.filter(name__icontains=q)

    categories = (
        categories.order_by("-paper_count", "name")
        if sort == "count"
        else categories.order_by("name")
    )

    can_upload = (
        request.user.userprofile.role == 'verified'
        and getattr(request.user.userprofile, 'can_upload', False)
    )

    return render(request, 'core/capstones.html', {
        'categories': categories,
        'can_upload': can_upload,
    })

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def capstone_list_by_category(request, category):
    cat = get_object_or_404(Category, slug=category)

    q      = (request.GET.get('q') or '').strip()
    year   = (request.GET.get('year') or '').strip()
    subcat = (request.GET.get('subcategory') or '').strip()
    sort   = (request.GET.get('sort') or '').strip()

    qs = CapstonePaper.objects.filter(category=cat)

    if year.isdigit():
        qs = qs.filter(publication_year=int(year))
    if subcat:
        qs = qs.filter(subcategory__name=subcat)

    if q:
        ft = (
            Q(title__icontains=q) |
            Q(abstract__icontains=q) |
            Q(authors__icontains=q) |
            Q(instructor__icontains=q) |
            Q(category__name__icontains=q) |
            Q(subcategory__name__icontains=q) |
            Q(tags__name__icontains=q)
        )
        if q.isdigit():
            ft |= Q(publication_year=int(q))
        qs = qs.filter(ft).distinct()

    # sorting
    if sort == 'year_asc':
        qs = qs.order_by('publication_year', 'title')
    elif sort == 'title_asc':
        qs = qs.order_by('title')
    else:
        qs = qs.order_by('-publication_year', 'title')

    years = (
        CapstonePaper.objects
        .filter(category=cat)
        .values_list('publication_year', flat=True)
        .distinct()
        .order_by('-publication_year')
    )
    subcategories = (
        SubCategory.objects
        .filter(category=cat)
        .values_list('name', flat=True)
        .distinct()
    )

    approved_ids = PaperAccessRequest.objects.filter(
        user=request.user,
        status='approved'
    ).values_list('paper_id', flat=True)

    can_upload = (
        request.user.userprofile.role == 'verified'
        and getattr(request.user.userprofile, 'can_upload', False)
    )

    return render(request, 'core/capstone_list.html', {
        'category':             cat,
        'papers':               qs,
        'search_query':         q,
        'selected_year':        year,
        'years':                years,
        'selected_subcategory': subcat,
        'subcategories':        subcategories,
        'approved_access_ids':  list(approved_ids),
        'can_upload':           can_upload,
    })

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def edit_paper_view(request, paper_id):
    # Instructors & Admins can edit any paper.
    # Verified users can edit only their own paper.
    paper = get_object_or_404(CapstonePaper, id=paper_id)

    role = getattr(getattr(request.user, 'userprofile', None), 'role', 'non_verified')
    is_admin_or_instr = role in ['admin', 'instructor']
    is_verified_owner = (role == 'verified' and paper.uploaded_by == request.user)

    if not (is_admin_or_instr or is_verified_owner):
        messages.error(request, "You don't have permission to edit this paper.")
        return redirect('capstones_by_category', category=paper.category.slug)

    if request.method == 'POST':
        form = CapstonePaperForm(request.POST, request.FILES, instance=paper)
        if form.is_valid():
            paper = form.save(commit=False)

            # Re-classify on edit (kept from your original logic)
            cat_name, sub_name, tag_list = classify_paper_ml(
                form.cleaned_data['title'],
                form.cleaned_data['abstract']
            )
            paper.category, _ = Category.objects.get_or_create(name=cat_name)
            paper.subcategory, _ = SubCategory.objects.get_or_create(name=sub_name, category=paper.category)
            paper.save()

            paper.tags.clear()
            for name in tag_list:
                tag_obj, _ = Tag.objects.get_or_create(name=name)
                paper.tags.add(tag_obj)

            messages.success(request, 'Capstone paper updated successfully.')
            if is_admin_or_instr:
                return redirect('capstones_by_category', category=paper.category.slug)
            return redirect('verified_dashboard')
    else:
        form = CapstonePaperForm(instance=paper)

    return render(request, 'core/edit_paper.html', {'form': form, 'paper': paper})

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def delete_paper_view(request, paper_id):
    """
    Admin & Instructor: can delete any paper.
    Verified: can delete only their own paper.
    Others: cannot delete.
    """
    paper = get_object_or_404(CapstonePaper, id=paper_id)
    role = getattr(getattr(request.user, 'userprofile', None), 'role', 'non_verified')

    is_admin_or_instr = (role in ['admin', 'instructor'])
    is_verified_owner = (role == 'verified' and paper.uploaded_by == request.user)

    if not (is_admin_or_instr or is_verified_owner):
        messages.error(request, "You don't have permission to delete this paper.")
        return redirect('capstones_by_category', category=paper.category.slug)

    if request.method == 'POST':
        category    = paper.category
        subcategory = paper.subcategory
        cat_slug    = category.slug if category else None

        has_other_in_cat = bool(
            category and CapstonePaper.objects.filter(category=category).exclude(id=paper.id).exists()
        )
        has_other_in_sub = bool(
            subcategory and CapstonePaper.objects.filter(subcategory=subcategory).exclude(id=paper.id).exists()
        )

        title = paper.title
        paper.delete()

        # Optional cleanup if nothing else references these
        if category and not has_other_in_cat:
            category.delete()
        if subcategory and not has_other_in_sub:
            subcategory.delete()

        messages.success(request, f"“{title}” was deleted successfully.")

        if cat_slug and has_other_in_cat and Category.objects.filter(slug=cat_slug).exists():
            return redirect('capstones_by_category', category=cat_slug)
        return redirect('capstones_main')

    messages.info(request, "Deletion must be confirmed via the modal.")
    return redirect('capstones_by_category', category=paper.category.slug)


# NEW ── Cancel upload (kept name for compatibility; no status checks anymore)
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def cancel_revision(request, paper_id):
    if request.method != 'POST':
        messages.error(request, "Invalid request method.")
        return redirect('verified_dashboard')

    paper = get_object_or_404(CapstonePaper, id=paper_id)

    if paper.uploaded_by != request.user:
        messages.error(request, "You can only cancel your own paper.")
        return redirect('verified_dashboard')

    title = paper.title
    paper.delete()
    messages.success(request, f"'{title}' has been removed.")
    return redirect('verified_dashboard')

# ── Upload Access Management ────────────────────────────────────────────────────

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['instructor'])
def manage_upload_access(request):
    users = UserProfile.objects.filter(role='verified')
    return render(request, 'core/manage_upload_access.html', {'users': users})

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['instructor'])
def toggle_upload_access(request, user_id):
    profile = get_object_or_404(UserProfile, user__id=user_id, role='verified')
    profile.can_upload = not profile.can_upload
    profile.save()
    msg = "granted" if profile.can_upload else "revoked"
    messages.success(request, f"{profile.user.username}: upload {msg}.")
    return redirect('manage_upload_access')

# ── Paper Access Requests ──────────────────────────────────────────────────────

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def request_access_view(request, paper_id):
    paper   = get_object_or_404(CapstonePaper, id=paper_id)
    profile = request.user.userprofile

    # Instructors/Admins should NOT request access; they can view directly.
    if profile.role in ['admin', 'instructor']:
        messages.info(request, "Instructors and admins can view all papers without requesting access.")
        return redirect('capstones_by_category', category=paper.category.slug)

    if request.method == 'POST':
        form = PaperAccessRequestForm(request.POST)
        if form.is_valid():
            req = form.save(commit=False)
            req.user    = request.user
            req.paper   = paper
            req.status  = 'pending'
            req.save()
            messages.success(request, "Access request submitted!")
            return redirect('capstones_main')
    else:
        form = PaperAccessRequestForm()
        if profile.role == 'verified':
            # Verified users don't need address/phone
            form.fields['address'].widget = forms.HiddenInput()
            form.fields['phone'].widget   = forms.HiddenInput()

    return render(request, 'core/request_access.html', {'form': form, 'paper': paper})

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['admin', 'instructor'])
def access_request_list(request):
    reqs = PaperAccessRequest.objects.select_related('user', 'paper').order_by('-requested_at')
    return render(request, 'core/access_request_list.html', {'requests': reqs})

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['admin', 'instructor'])
def approve_access_request(request, request_id):
    req = get_object_or_404(PaperAccessRequest, id=request_id)
    req.status = 'approved'
    req.save()
    messages.success(request, f"Approved access for '{req.paper.title}' by {req.user.username}")
    return redirect('access_request_list')

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['admin', 'instructor'])
def reject_access_request(request, request_id):
    req = get_object_or_404(PaperAccessRequest, id=request_id)
    req.status = 'rejected'
    req.save()
    messages.error(request, f"Rejected access for '{req.paper.title}' by {req.user.username}")
    return redirect('access_request_list')

# ── Watermarked PDF Viewing ────────────────────────────────────────────────────
def _merge_page(base_page, overlay_page):
    try:
        base_page.merge_page(overlay_page)   # PyPDF2 >= 2.x
    except AttributeError:
        base_page.mergePage(overlay_page)    # older PyPDF2

def _auto_font_size(w: float, h: float) -> int:
    return max(100, min(220, int(min(w, h) * 0.14)))  # ~14%

def _make_watermark_page(w: float, h: float, text: str, font="Helvetica-Bold"):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(w, h))
    font_size = max(110, min(240, int(min(w, h) * 0.15)))
    c.setFont(font, font_size)
    c.saveState()
    light_grey = Color(0.5, 0.5, 0.5, alpha=0.15)
    c.setFillColor(light_grey)
    c.translate(w / 2.0, h / 2.0)
    c.drawCentredString(0, 0, text)
    c.restoreState()
    c.showPage()
    c.save()
    buf.seek(0)
    return PdfReader(buf)

def _add_watermark_to_pdf(input_pdf_path: str, watermark_text: str) -> io.BytesIO:
    reader = PdfReader(input_pdf_path)
    writer = PdfWriter()

    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception:
            raise Http404("PDF is encrypted and cannot be processed.")

    for page in reader.pages:
        w = float(page.mediabox.width)
        h = float(page.mediabox.height)
        wm_reader = _make_watermark_page(w, h, watermark_text)
        wm_page = wm_reader.pages[0]
        _merge_page(page, wm_page)
        writer.add_page(page)

    out = io.BytesIO()
    writer.write(out)
    out.seek(0)
    return out

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def view_paper(request, paper_id):
    paper = get_object_or_404(CapstonePaper, id=paper_id)

    role = getattr(getattr(request.user, 'userprofile', None), 'role', 'non_verified')
    is_admin_or_instr = role in ['admin', 'instructor']
    is_uploader       = (paper.uploaded_by_id == request.user.id)
    is_verified       = (role == 'verified')

    if not (is_admin_or_instr or is_uploader):
        if is_verified:
            # Verified users can view directly.
            pass
        else:
            # Non-verified must have an approved access request
            has_access = PaperAccessRequest.objects.filter(
                user=request.user, paper=paper, status='approved'
            ).exists()
            if not has_access:
                messages.error(request, "You don't have access to view this paper.")
                return redirect('capstones_by_category', category=paper.category.slug)

    file_field = getattr(paper, "file", None)
    if not file_field or not getattr(file_field, "name", ""):
        raise Http404("PDF not found for this paper.")
    original_pdf_path = file_field.path

    watermark_text = "EVSU"
    watermarked_pdf = _add_watermark_to_pdf(original_pdf_path, watermark_text)

    now = timezone.localtime()
    ay = academic_year_for(now, start_month=8)
    PaperViewEvent.objects.create(paper=paper, user=request.user, ay=ay)

    safe_name = slugify(paper.title) or f"paper-{paper.id}"
    filename = f"{safe_name}-watermarked.pdf"

    response = FileResponse(
        watermarked_pdf,
        as_attachment=False,
        filename=filename,
        content_type="application/pdf",
    )
    response["Content-Disposition"] = f'inline; filename="{filename}"'
    return response

# ── Trends (visible to all logged-in users) ────────────────────────────────────

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

    yearly = (qs.values("publication_year")
                .annotate(count=Count("id"))
                .order_by("publication_year"))
    years = [str(r["publication_year"]) for r in yearly]
    counts = [r["count"] for r in yearly]

    by_cat_year = (qs.values("publication_year", "category__name")
                     .annotate(count=Count("id"))
                     .order_by("publication_year", "category__name"))
    categories = sorted({r["category__name"] or "Uncategorized" for r in by_cat_year})
    idx_map = {y: i for i, y in enumerate(years)}
    cat_series = {c: [0] * len(years) for c in categories}
    for r in by_cat_year:
        c = r["category__name"] or "Uncategorized"
        y = str(r["publication_year"])
        if y in idx_map:
            cat_series[c][idx_map[y]] = r["count"]

    return JsonResponse({
        "yearly": {"labels": years, "counts": counts},
        "stackedByCategory": {
            "labels": years,
            "series": [{"name": c, "data": cat_series[c]} for c in categories],
        }
    })

# NEW: Most-accessed within School Year
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def most_accessed_api(request):
    ay = request.GET.get('ay')
    if not ay:
        ay = academic_year_for(timezone.localtime(), start_month=8)

    top_qs = (
        PaperViewEvent.objects
        .filter(ay=ay)
        .values('paper_id', 'paper__title', 'paper__authors')
        .annotate(views=Count('id'))
        .order_by('-views')[:10]
    )

    monthly = (
        PaperViewEvent.objects
        .filter(ay=ay)
        .annotate(m=TruncMonth('viewed_at'))
        .values('m')
        .annotate(views=Count('id'))
        .order_by('m')
    )

    return JsonResponse({
        "ay": ay,
        "topPapers": [{
            "paperId": r["paper_id"],
            "title": r["paper__title"],
            "authors": r["paper__authors"],
            "views": r["views"]
        } for r in top_qs],
        "monthly": {
            "labels": [d["m"].strftime("%b %Y") for d in monthly],
            "views": [d["views"] for d in monthly]
        }
    })
