from .models import UserProfile, CapstonePaper

def _compute_can_upload(request):
    # Must be logged in
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return False

    # Must be a verified user with instructor-granted permission
    try:
        profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        return False
    if profile.role != 'verified':
        return False

    # Since there's no status field anymore, just check if they have upload permission
    return bool(profile.can_upload)

def can_upload_flag(request):
    """Expose `can_upload` to all templates (used by base.html sidebar)."""
    return {'can_upload': _compute_can_upload(request)}

# Optional alias kept for backward compatibility
def upload_permission(request):
    return can_upload_flag(request)