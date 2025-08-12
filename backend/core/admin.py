from django.contrib import admin
from .models import (
    UserProfile, Category, SubCategory, Tag, CapstonePaper, PaperAccessRequest
)

# UserProfile Admin
@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'can_upload')
    list_filter = ('role', 'can_upload')
    search_fields = ('user__email', 'user__first_name', 'user__last_name')

# Category Admin
@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)

# SubCategory Admin
@admin.register(SubCategory)
class SubCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'category')
    list_filter = ('category',)
    search_fields = ('name',)

# Tag Admin
@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)

# CapstonePaper Admin
@admin.register(CapstonePaper)
class CapstonePaperAdmin(admin.ModelAdmin):
    list_display = ('title', 'uploaded_by', 'category', 'status', 'uploaded_at')
    list_filter = ('status', 'category', 'publication_year')
    search_fields = ('title', 'abstract', 'uploaded_by__email')

    actions = ['approve_papers', 'mark_for_revision']

    def approve_papers(self, request, queryset):
        queryset.update(status='approved')
        self.message_user(request, "Selected papers marked as approved.")

    def mark_for_revision(self, request, queryset):
        queryset.update(status='revise')
        self.message_user(request, "Selected papers marked for revision.")

# PaperAccessRequest Admin
@admin.register(PaperAccessRequest)
class PaperAccessRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'paper', 'status', 'requested_at')
    list_filter = ('status', 'requested_at')
    search_fields = ('user__email', 'paper__title', 'reason')
