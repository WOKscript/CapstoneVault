# backend/core/forms.py

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordChangeForm

from .models import (
    UserProfile,
    CapstonePaper,
    PaperAccessRequest,
    Adviser,
)

# =========================
# AUTH FORMS
# =========================

class SignupForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control"}),
        min_length=8
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control"}),
        min_length=8
    )

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]
        widgets = {
            "first_name": forms.TextInput(attrs={"class": "form-control", "placeholder": "First name"}),
            "last_name": forms.TextInput(attrs={"class": "form-control", "placeholder": "Last name"}),
            "email": forms.EmailInput(attrs={"class": "form-control", "placeholder": "Email"}),
        }

    def clean_email(self):
        email = (self.cleaned_data.get("email") or "").strip()
        if not email:
            raise forms.ValidationError("Email is required.")
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean(self):
        cleaned = super().clean()
        pw = cleaned.get("password")
        cpw = cleaned.get("confirm_password")
        if pw and cpw and pw != cpw:
            self.add_error("confirm_password", "Passwords do not match.")
        return cleaned


class LoginForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={"class": "form-control", "placeholder": "Email"})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Password"})
    )


# =========================
# CAPSTONE FORMS
# =========================

class CapstonePaperForm(forms.ModelForm):
    class Meta:
        model = CapstonePaper
        fields = ["title", "abstract", "authors", "adviser", "publication_year", "file"]
        labels = {"adviser": "Adviser"}
        widgets = {
            "title": forms.TextInput(attrs={"class": "form-control", "placeholder": "Enter title"}),
            "abstract": forms.Textarea(attrs={
                "class": "form-control",
                "style": "height: 150px; resize: none;",
                "placeholder": "Enter abstract here...",
            }),
            "authors": forms.TextInput(attrs={"class": "form-control", "placeholder": "Enter authors"}),
            "adviser": forms.Select(attrs={"class": "form-select"}),  # dropdown
            "publication_year": forms.NumberInput(attrs={"class": "form-control", "placeholder": "e.g. 2025"}),
            "file": forms.ClearableFileInput(attrs={"class": "form-control", "accept": "application/pdf"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # ✅ Make adviser show "Select adviser" instead of "---------"
        # Note: if Adviser has __str__ returning "Last, First", this will look nice.
        self.fields["adviser"].empty_label = "Select adviser"

        # Optional: keep adviser list ordered
        try:
            self.fields["adviser"].queryset = Adviser.objects.all().order_by("last_name", "first_name")
        except Exception:
            pass


class PaperAccessRequestForm(forms.ModelForm):
    class Meta:
        model = PaperAccessRequest
        fields = ["reason", "address", "phone"]
        widgets = {
            "reason": forms.Textarea(attrs={"class": "form-control", "rows": 4, "placeholder": "Reason for access"}),
            "address": forms.TextInput(attrs={"class": "form-control", "placeholder": "Address"}),
            "phone": forms.TextInput(attrs={"class": "form-control", "placeholder": "Phone"}),
        }


# =========================
# ADVISER MANAGEMENT FORM
# =========================

class AdviserForm(forms.ModelForm):
    class Meta:
        model = Adviser
        fields = ["first_name", "last_name"]
        widgets = {
            "first_name": forms.TextInput(attrs={"class": "form-control", "placeholder": "First name"}),
            "last_name": forms.TextInput(attrs={"class": "form-control", "placeholder": "Last name"}),
        }


# =========================
# PROFILE SETTINGS FORMS
# =========================

class UserAccountForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]
        widgets = {
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
        }


class AvatarForm(forms.ModelForm):
    remove_avatar = forms.BooleanField(required=False)

    class Meta:
        model = UserProfile
        fields = ["avatar"]


class StyledPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Current password"})
    )
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "New password"})
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Confirm new password"})
    )


# =========================
# PREFERENCES + SUPPORT
# =========================

class PreferencesForm(forms.Form):
    compact_mode = forms.BooleanField(required=False)
    show_tips = forms.BooleanField(required=False, initial=True)


class SupportForm(forms.Form):
    subject = forms.CharField(
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Subject"}),
        max_length=150
    )
    message = forms.CharField(
        widget=forms.Textarea(attrs={"class": "form-control", "rows": 5, "placeholder": "Describe your concern"}),
    )
    page = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Page (optional)"}),
        max_length=200
    )
