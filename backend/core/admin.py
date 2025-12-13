from django.contrib import admin
from .models import (
    UserProfile, Category, SubCategory, Tag,
    CapstonePaper, PaperAccessRequest, Adviser
)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display  = ("user", "role", "can_upload")
    list_filter   = ("role", "can_upload")
    search_fields = ("user__username", "user__email", "user__first_name", "user__last_name")


@admin.register(Adviser)
class AdviserAdmin(admin.ModelAdmin):
    list_display  = ("last_name", "first_name")
    search_fields = ("first_name", "last_name")
    ordering      = ("last_name", "first_name")


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display  = ("name",)
    search_fields = ("name",)


@admin.register(SubCategory)
class SubCategoryAdmin(admin.ModelAdmin):
    list_display  = ("name", "category")
    list_filter   = ("category",)
    search_fields = ("name", "category__name")


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display  = ("name",)
    search_fields = ("name",)


@admin.register(CapstonePaper)
class CapstonePaperAdmin(admin.ModelAdmin):
    list_display  = (
        "title", "uploaded_by", "category", "subcategory",
        "publication_year", "adviser", "uploaded_at",
    )
    list_filter   = ("category", "subcategory", "publication_year", "uploaded_at", "adviser")
    search_fields = (
        "title", "abstract", "authors",
        "adviser__first_name", "adviser__last_name",
        "uploaded_by__username", "uploaded_by__email",
    )
    date_hierarchy = "uploaded_at"
    ordering       = ("-uploaded_at",)


@admin.register(PaperAccessRequest)
class PaperAccessRequestAdmin(admin.ModelAdmin):
    list_display  = ("user", "paper", "status", "requested_at")
    list_filter   = ("status", "requested_at")
    search_fields = ("user__username", "user__email", "paper__title", "reason")
    date_hierarchy = "requested_at"
    ordering       = ("-requested_at",)
