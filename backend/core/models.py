from django.db import models
from django.contrib.auth.models import User
from django.utils.text import slugify
from django.utils import timezone

# USER PROFILE
class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('instructor', 'Instructor'),
        ('verified', 'Verified User'),
        ('non_verified', 'Non-Verified User'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='non_verified')
    can_upload = models.BooleanField(default=False)  # Granted by Instructor
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.role}"


# ADVISER (Admin-managed dropdown source)
class Adviser(models.Model):
    first_name = models.CharField(max_length=100)
    last_name  = models.CharField(max_length=100)

    class Meta:
        unique_together = ("first_name", "last_name")
        ordering = ["last_name", "first_name"]

    def __str__(self):
        return f"{self.last_name}, {self.first_name}"


# CATEGORY
class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


# SUBCATEGORY
class SubCategory(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='subcategories')
    name = models.CharField(max_length=100)

    class Meta:
        unique_together = ['category', 'name']

    def __str__(self):
        return f"{self.name} ({self.category.name})"


# TAG
class Tag(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name


# CAPSTONE PAPER
class CapstonePaper(models.Model):
    title = models.CharField(max_length=255)
    abstract = models.TextField(blank=True)
    authors = models.CharField(max_length=255, blank=True)
    file = models.FileField(upload_to='capstone_pdfs/', max_length=255)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    publication_year = models.IntegerField(null=True, blank=True)

    # Adviser dropdown (managed in admin)
    adviser = models.ForeignKey(Adviser, on_delete=models.SET_NULL, null=True, blank=True)

    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    subcategory = models.ForeignKey(SubCategory, on_delete=models.SET_NULL, null=True, blank=True)
    tags = models.ManyToManyField(Tag, blank=True)

    def __str__(self):
        return self.title


class PaperAccessRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    paper = models.ForeignKey(CapstonePaper, on_delete=models.CASCADE)
    reason = models.TextField()
    address = models.CharField(max_length=255, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)

    # Expiry support
    approved_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['user', 'paper']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.paper.title} ({self.status})"

    @property
    def is_active(self) -> bool:
        return (
            self.status == 'approved'
            and self.expires_at is not None
            and self.expires_at >= timezone.now()
        )


# Real view events for trends by School Year
class PaperViewEvent(models.Model):
    paper = models.ForeignKey(CapstonePaper, on_delete=models.CASCADE, related_name='view_events')
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    viewed_at = models.DateTimeField(auto_now_add=True)
    ay = models.CharField(max_length=9, db_index=True)  # e.g., "2024-2025"

    class Meta:
        indexes = [
            models.Index(fields=['ay']),
            models.Index(fields=['paper', 'ay']),
        ]

    def __str__(self):
        return f"View p#{self.paper_id} @ {self.ay}"


class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('user_created', 'User Created'),
        ('user_updated', 'User Updated'),
        ('user_deleted', 'User Deleted'),
        ('user_login', 'User Login'),
        ('user_logout', 'User Logout'),
        ('password_reset', 'Password Reset'),
        ('role_changed', 'Role Changed'),
        ('paper_uploaded', 'Paper Uploaded'),
        ('paper_edited', 'Paper Edited'),
        ('paper_deleted', 'Paper Deleted'),
        ('paper_viewed', 'Paper Viewed'),
        ('access_granted', 'Access Granted'),
        ('access_denied', 'Access Denied'),
        ('upload_permission_changed', 'Upload Permission Changed'),
        ('support_request', 'Support Request'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs_performed')
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    target_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs_received'
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['user']),
            models.Index(fields=['action']),
        ]

    def __str__(self):
        return f"{self.user.username if self.user else 'System'} - {self.get_action_display()} - {self.created_at}"
