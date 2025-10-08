from .models import AuditLog

def create_audit_log(user, action, description, ip_address=None, target_user=None, metadata=None):
    """Create an audit log entry"""
    return AuditLog.objects.create(
        user=user,
        action=action,
        description=description,
        ip_address=ip_address,
        target_user=target_user,
        metadata=metadata or {}
    )

def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip