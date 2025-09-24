from django.db import models
from django.contrib.auth.models import User
from django.utils.text import slugify

# USER PROFILE
class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('adviser', 'Adviser'),
        ('verified', 'Verified User'),
        ('non_verified', 'Non-Verified User'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='non_verified')
    can_upload = models.BooleanField(default=False)  # Granted by Adviser

    def __str__(self):
        return f"{self.user.username} - {self.role}"

# CATEGORY (e.g., IoT, Machine Learning)
class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

# SUBCATEGORY (e.g., IoT in Agriculture)
class SubCategory(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='subcategories')
    name = models.CharField(max_length=100)

    class Meta:
        unique_together = ['category', 'name']

    def __str__(self):
        return f"{self.name} ({self.category.name})"

# TAG (e.g., "Sensors", "Cloud", "Farm")
class Tag(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name

# CAPSTONE PAPER (extended)
class CapstonePaper(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('revise', 'Revise'),
    ]

    title = models.CharField(max_length=255)
    abstract = models.TextField(blank=True)
    authors = models.CharField(max_length=255, blank=True)
    file = models.FileField(upload_to='capstone_pdfs/')
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    publication_year = models.IntegerField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    adviser = models.CharField(max_length=255, blank=True, null=True)
    feedback = models.TextField(blank=True, null=True)

    # RELATIONSHIPS
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    subcategory = models.ForeignKey(SubCategory, on_delete=models.SET_NULL, null=True, blank=True)
    tags = models.ManyToManyField(Tag, blank=True)

    def __str__(self):
        return self.title

class PaperAccessRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    paper = models.ForeignKey(CapstonePaper, on_delete=models.CASCADE)
    reason = models.TextField()
    address = models.CharField(max_length=255, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    status = models.CharField(max_length=20,
                              choices=[('pending', 'Pending'),
                                       ('approved', 'Approved'),
                                       ('rejected', 'Rejected')],
                              default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.paper.title} ({self.status})"

# NEW: log real views for trend analytics by School Year
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
