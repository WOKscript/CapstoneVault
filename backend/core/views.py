# ============================
# core/views.py  (FULL FILE)
# ============================
import os
import io
import joblib
from datetime import datetime

from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
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
    RejectionFeedbackForm,
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

# ── Authentication & Signup ───────────────────────────────────────────────────

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
def logout_view(request):
    # Standard logout fully clears auth + session id
    logout(request)
    request.session.flush()
    # Redirect to login (or change to 'dashboard' if you prefer)
    resp = redirect('login')
    # Extra guard so the redirect response itself isn't cached
    resp['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp['Pragma'] = 'no-cache'
    resp['Expires'] = '0'
    return resp


def signup_view(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email', '').strip()

            # Prevent duplicate emails (default Django User doesn't enforce this)
            if User.objects.filter(email__iexact=email).exists():
                form.add_error('email', 'An account with this email already exists.')
                return render(request, 'core/signup.html', {'form': form})

            user = form.save(commit=False)

            # Ensure a unique username even if the form doesn't provide one
            if not getattr(user, 'username', None):
                user.username = _unique_username_from_email(email)

            # If your form uses a single 'password' field (as in your current setup)
            user.set_password(form.cleaned_data['password'])
            # If you later switch to UserCreationForm style, use:
            # user.set_password(form.cleaned_data['password1'])

            user.email = email
            user.save()

            # Assign role by domain
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
    if request.method == 'GET' and 'next' in request.GET:
        return redirect('login')

    if request.user.is_authenticated:
        try:
            role = request.user.userprofile.role
        except UserProfile.DoesNotExist:
            role = 'admin' if request.user.is_superuser else 'non_verified'
            UserProfile.objects.create(user=request.user, role=role)
        return redirect_dashboard_based_on_role(request, role)

    form = LoginForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = authenticate(
            request,
            email=form.cleaned_data['email'],
            password=form.cleaned_data['password']
        )
        if user:
            request.session.cycle_key()
            login(request, user)
            try:
                role = user.userprofile.role
            except UserProfile.DoesNotExist:
                role = 'admin' if user.is_superuser else 'non_verified'
                UserProfile.objects.create(user=user, role=role)
            return redirect_dashboard_based_on_role(request, role)
        form.add_error(None, "Invalid email or password.")

    return render(request, 'core/login.html', {'form': form})


def redirect_dashboard_based_on_role(request, role):
    if role == 'admin':
        return redirect('admin_dashboard')
    elif role == 'adviser':
        return redirect('adviser_dashboard')
    elif role == 'verified':
        return redirect('verified_dashboard')
    elif role == 'non_verified':
        return redirect('non_verified_dashboard')
    else:
        messages.error(request, f"Unknown role: {role}. Contact admin.")
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
@role_required(['adviser'])
def adviser_dashboard(request):
    pending_count  = CapstonePaper.objects.filter(status='pending').count()
    approved_count = CapstonePaper.objects.filter(status='approved').count()
    revise_count   = CapstonePaper.objects.filter(status='revise').count()
    recent_papers  = CapstonePaper.objects.order_by('-uploaded_at')[:5]

    context = {
        'pending_count': pending_count,
        'approved_count': approved_count,
        'revise_count': revise_count,
        'recent_papers': recent_papers,
    }
    return render(request, 'core/dashboard_adviser.html', context)

@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['verified'])
def verified_dashboard(request):
    user = request.user
    pending_or_revise = CapstonePaper.objects.filter(
        uploaded_by=user,
        status__in=['pending', 'revise']
    ).count()

    can_upload      = user.userprofile.can_upload and (pending_or_revise == 0)
    recent_requests = PaperAccessRequest.objects.filter(user=user).order_by('-requested_at')[:5]
    revised_papers  = CapstonePaper.objects.filter(
        uploaded_by=user,
        status='revise'
    ).order_by('-uploaded_at')

    context = {
        'can_upload': can_upload,
        'recent_requests': recent_requests,
        'revised_papers': revised_papers,
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
        messages.warning(request, "Your adviser has not granted you upload permission.")
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

            paper.status = 'approved' if profile.role == 'admin' else 'pending'
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
    categories = Category.objects.annotate(paper_count=Count('capstonepaper'))
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

    q      = request.GET.get('q', '').strip()
    year   = request.GET.get('year', '')
    subcat = request.GET.get('subcategory', '')

    qs = CapstonePaper.objects.filter(category=cat, status='approved')

    if year.isdigit():
        qs = qs.filter(publication_year=int(year))
    if subcat:
        qs = qs.filter(subcategory__name=subcat)

    if q:
        ft = (
            Q(title__icontains=q) |
            Q(abstract__icontains=q) |
            Q(authors__icontains=q) |
            Q(adviser__icontains=q) |
            Q(category__name__icontains=q) |
            Q(subcategory__name__icontains=q) |
            Q(tags__name__icontains=q)
        )
        if q.isdigit():
            ft |= Q(publication_year=int(q))
        qs = qs.filter(ft).distinct()

    papers = qs.order_by('-publication_year')

    years = (
        CapstonePaper.objects
        .filter(category=cat, status='approved')
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
        'papers':               papers,
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
    paper      = get_object_or_404(CapstonePaper, id=paper_id, uploaded_by=request.user)
    old_status = paper.status

    if request.method == 'POST':
        form = CapstonePaperForm(request.POST, request.FILES, instance=paper)
        if form.is_valid():
            paper = form.save(commit=False)

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

            if old_status == 'revise':
                paper.status   = 'pending'
                paper.feedback = ''
                paper.save()

            messages.success(request, 'Capstone paper updated and sent back for review.')
            return redirect('verified_dashboard')
    else:
        form = CapstonePaperForm(instance=paper)

    return render(request, 'core/edit_paper.html', {'form': form, 'paper': paper})

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def delete_paper_view(request, paper_id):
    """
    Admin can delete any paper.
    Verified can delete only their own paper.
    Others cannot delete.
    No standalone confirmation page — use modal only.
    """
    paper = get_object_or_404(CapstonePaper, id=paper_id)
    role = getattr(getattr(request.user, 'userprofile', None), 'role', 'non_verified')

    is_admin = role == 'admin' or request.user.is_superuser
    is_verified_owner = role == 'verified' and paper.uploaded_by == request.user

    if not (is_admin or is_verified_owner):
        messages.error(request, "You don't have permission to delete this paper.")
        return redirect('capstones_by_category', category=paper.category.slug)

    if request.method == 'POST':
        category = paper.category
        subcategory = paper.subcategory
        cat_slug = category.slug if category else None

        has_other_in_cat = bool(
            category and CapstonePaper.objects.filter(category=category).exclude(id=paper.id).exists()
        )
        has_other_in_sub = bool(
            subcategory and CapstonePaper.objects.filter(subcategory=subcategory).exclude(id=paper.id).exists()
        )

        title = paper.title
        paper.delete()

        if category and not has_other_in_cat:
            category.delete()
        if subcategory and not has_other_in_sub:
            subcategory.delete()

        messages.success(request, f"“{title}” was deleted successfully.")

        if cat_slug and has_other_in_cat and Category.objects.filter(slug=cat_slug).exists():
            return redirect('capstones_by_category', category=cat_slug)
        return redirect('capstones_main')

    # If a GET request sneaks through, just redirect
    messages.info(request, "Deletion must be confirmed via the modal.")
    return redirect('capstones_by_category', category=paper.category.slug)


# NEW ── Cancel a pending/revise upload (for Verified users)
@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def cancel_revision(request, paper_id):
    """
    Allow the uploader to cancel/withdraw their own paper if it's still
    in 'pending' or 'revise'. We delete the record, which frees them to upload again.
    """
    if request.method != 'POST':
        messages.error(request, "Invalid request method.")
        return redirect('verified_dashboard')

    paper = get_object_or_404(CapstonePaper, id=paper_id)

    if paper.uploaded_by != request.user:
        messages.error(request, "You can only cancel your own paper.")
        return redirect('verified_dashboard')

    if paper.status not in ['pending', 'revise']:
        messages.warning(request, "This paper can no longer be cancelled.")
        return redirect('verified_dashboard')

    title = paper.title
    paper.delete()
    messages.success(request, f"'{title}' has been cancelled and removed.")
    return redirect('verified_dashboard')

# ── Adviser Review: Pending / Approve / Revise ─────────────────────────────────

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['adviser'])
def adviser_pending_papers(request):
    papers = CapstonePaper.objects.filter(status__in=['pending', 'revise'])
    return render(request, 'core/pending_papers_review.html', {
        'papers': papers,
        'reviewer_role': 'adviser'
    })

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['adviser'])
def adviser_approve_paper(request, paper_id):
    paper = get_object_or_404(CapstonePaper, id=paper_id)
    paper.status = 'approved'
    paper.save()
    messages.success(request, f"Paper '{paper.title}' approved.")
    return redirect('capstones_by_category', category=paper.category.slug)

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['adviser'])
def adviser_revise_paper(request, paper_id):
    paper = get_object_or_404(CapstonePaper, id=paper_id)
    if request.method == 'POST':
        form = RejectionFeedbackForm(request.POST)
        if form.is_valid():
            paper.status   = 'revise'
            paper.feedback = form.cleaned_data['feedback']
            paper.save()
            messages.success(request, f"Paper '{paper.title}' marked for revision.")
            return redirect('adviser_pending_papers')
    else:
        form = RejectionFeedbackForm()

    return render(request, 'core/revise_paper.html', {
        'form': form,
        'paper': paper,
        'reviewer_role': 'adviser'
    })

# ── Upload Access Management ────────────────────────────────────────────────────

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['adviser'])
def manage_upload_access(request):
    users = UserProfile.objects.filter(role='verified')
    return render(request, 'core/manage_upload_access.html', {'users': users})

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['adviser'])
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
            form.fields['address'].widget = forms.HiddenInput()
            form.fields['phone'].widget   = forms.HiddenInput()

    return render(request, 'core/request_access.html', {'form': form, 'paper': paper})

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['admin', 'adviser'])
def access_request_list(request):
    reqs = PaperAccessRequest.objects.select_related('user', 'paper').order_by('-requested_at')
    return render(request, 'core/access_request_list.html', {'requests': reqs})

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['admin', 'adviser'])
def approve_access_request(request, request_id):
    req = get_object_or_404(PaperAccessRequest, id=request_id)
    req.status = 'approved'
    req.save()
    messages.success(request, f"Approved access for '{req.paper.title}' by {req.user.username}")
    return redirect('access_request_list')

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
@role_required(['admin', 'adviser'])
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
    is_admin_or_adv = role in ['admin', 'adviser']
    is_uploader     = (paper.uploaded_by_id == request.user.id)
    is_verified     = (role == 'verified')

    # Admin/Adviser and Uploader: can view anything
    if not (is_admin_or_adv or is_uploader):
        # Verified users can view only APPROVED papers without a request
        if is_verified:
            if paper.status != 'approved':
                messages.error(request, "This paper isn't approved yet.")
                return redirect('capstones_by_category', category=paper.category.slug)
        else:
            # Non-verified: must be approved AND have approved access request
            if paper.status != 'approved':
                raise Http404("This paper is not available for viewing.")
            has_access = PaperAccessRequest.objects.filter(
                user=request.user, paper=paper, status='approved'
            ).exists()
            if not has_access:
                messages.error(request, "You don't have access to view this paper.")
                return redirect('capstones_by_category', category=paper.category.slug)

    # Get file
    file_field = getattr(paper, "file", None)
    if not file_field or not getattr(file_field, "name", ""):
        raise Http404("PDF not found for this paper.")
    original_pdf_path = file_field.path

    # Watermark (grey, semi-opaque)
    watermark_text = "EVSU"
    watermarked_pdf = _add_watermark_to_pdf(original_pdf_path, watermark_text)

    # Log view
    now = timezone.localtime()
    ay = academic_year_for(now, start_month=8)
    PaperViewEvent.objects.create(paper=paper, user=request.user, ay=ay)

    safe_name = slugify(paper.title) or f"paper-{paper.id}"
    filename = f"{safe_name}-watermarked.pdf"

    # Force inline display
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
    # Only approved; ignore NULL years (works for IntegerField or CharField)
    return (CapstonePaper.objects
            .filter(status='approved')
            .exclude(publication_year__isnull=True))

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def trends_dashboard(request):
    return render(request, "core/trends.html")

@never_cache
@cache_control(no_store=True, no_cache=True, must_revalidate=True, max_age=0)
@login_required
def trends_api(request):
    """
    Returns:
      - yearly: labels (years), counts
      - stackedByCategory: labels (years), series [{name, data}]
    """
    qs = _trends_qs()

    # A) Papers per year
    yearly = (qs.values("publication_year")
                .annotate(count=Count("id"))
                .order_by("publication_year"))
    years = [str(r["publication_year"]) for r in yearly]
    counts = [r["count"] for r in yearly]

    # B) Stacked by category per year
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

    # Top 10 papers within AY
    top_qs = (
        PaperViewEvent.objects
        .filter(ay=ay)
        .values('paper_id', 'paper__title', 'paper__authors')
        .annotate(views=Count('id'))
        .order_by('-views')[:10]
    )

    # Monthly trend within AY
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
