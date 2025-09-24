# core/forms.py
from django import forms
from django.contrib.auth.models import User
from django.utils import timezone
import re

from .models import CapstonePaper, PaperAccessRequest


# ===== LOGIN ================================================================
class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        "class": "form-control",
        "placeholder": "Enter your email",
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control",
        "placeholder": "Enter your password",
    }))


# ===== SIGNUP ===============================================================
class SignupForm(forms.ModelForm):
    first_name = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control",
        "placeholder": "Enter your first name",
    }))
    last_name = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control",
        "placeholder": "Enter your last name",
    }))
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        "class": "form-control",
        "placeholder": "Enter your email",
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control",
        "placeholder": "Create a password",
    }))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control",
        "placeholder": "Repeat your password",
    }))

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "password"]

    def clean_email(self):
        email = (self.cleaned_data.get("email") or "").strip()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("This email is already registered.")
        return email

    def clean_password(self):
        password = self.cleaned_data.get("password") or ""
        if len(password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", password):
            raise forms.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            raise forms.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r"[0-9]", password):
            raise forms.ValidationError("Password must contain at least one number.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise forms.ValidationError("Password must contain at least one special character.")
        return password

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password")
        p2 = cleaned.get("confirm_password")
        if p1 and p2 and p1 != p2:
            self.add_error("confirm_password", "Passwords do not match.")
        return cleaned


# ===== CAPSTONE PAPER =======================================================
class CapstonePaperForm(forms.ModelForm):
    """Upload/edit form. Category/subcategory/tags are auto-filled by ML in views."""
    class Meta:
        model = CapstonePaper
        # adviser → instructor; status/feedback are intentionally NOT here
        fields = ["title", "abstract", "authors", "file", "publication_year", "instructor"]
        widgets = {
            "title": forms.TextInput(attrs={"class": "form-control", "placeholder": "Enter title"}),
            "abstract": forms.Textarea(attrs={
                "class": "form-control",
                "style": "height: 150px; resize: none;",
                "placeholder": "Enter abstract here...",
            }),
            "authors": forms.TextInput(attrs={"class": "form-control", "placeholder": "Enter authors"}),
            # Hint the browser we want PDFs
            "file": forms.ClearableFileInput(attrs={"class": "form-control", "accept": "application/pdf"}),
            "publication_year": forms.NumberInput(attrs={"class": "form-control no-spinner", "placeholder": "e.g. 2025"}),
            "instructor": forms.TextInput(attrs={"class": "form-control", "placeholder": "Enter instructor name"}),
        }

    def clean_publication_year(self):
        year = self.cleaned_data.get("publication_year")
        if year is None:
            return year
        current = timezone.now().year
        if year < 1900 or year > current + 1:
            raise forms.ValidationError(f"Year must be between 1900 and {current + 1}.")
        return year

    def clean_file(self):
        f = self.cleaned_data.get("file")
        if not f:
            return f
        # basic pdf check
        if not getattr(f, "content_type", "").lower().endswith("pdf"):
            raise forms.ValidationError("Please upload a PDF file.")
        if f.size > 20 * 1024 * 1024:  # 20 MB
            raise forms.ValidationError("File is too large (max 20MB).")
        return f


# ===== ACCESS REQUEST =======================================================
class PaperAccessRequestForm(forms.ModelForm):
    class Meta:
        model = PaperAccessRequest
        fields = ["reason", "address", "phone"]
        widgets = {
            "reason": forms.Textarea(attrs={"class": "form-control", "rows": 4}),
            "address": forms.TextInput(attrs={"class": "form-control"}),
            "phone": forms.TextInput(attrs={"class": "form-control"}),
        }
