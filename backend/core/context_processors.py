# core/context_processors.py
from .models import UserProfile, CapstonePaper

def _compute_can_upload(request):
    # Must be logged in
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return False

    # Must be a verified user with adviser‑granted permission
    try:
        profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        return False
    if profile.role != 'verified':
        return False

    # Must NOT have a paper in pending or revise
    has_pending_or_revise = CapstonePaper.objects.filter(
        uploaded_by=request.user,        # <- your field name
        status__in=['pending', 'revise']
    ).exists()

    return bool(profile.can_upload and not has_pending_or_revise)

def can_upload_flag(request):
    """Expose `can_upload` to all templates (used by base.html sidebar)."""
    return {'can_upload': _compute_can_upload(request)}

# Optional: keep this if your settings previously pointed to upload_permission
def upload_permission(request):
    return can_upload_flag(request)
