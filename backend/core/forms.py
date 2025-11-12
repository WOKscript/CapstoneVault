# core/forms.py
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordChangeForm
from django.core.exceptions import ValidationError
from django.utils import timezone
import re

from .models import CapstonePaper, PaperAccessRequest, UserProfile


# ===== LOGIN ================================================================
class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        "class": "form-control form-control-lg rounded-3",
        "placeholder": "Enter your email",
        "autocomplete": "email",
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control form-control-lg rounded-3",
        "placeholder": "Enter your password",
        "autocomplete": "current-password",
    }))


# ===== SIGNUP ===============================================================
class SignupForm(forms.ModelForm):
    first_name = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control form-control-lg rounded-3",
        "placeholder": "Enter your first name",
        "autocomplete": "given-name",
    }))
    last_name = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control form-control-lg rounded-3",
        "placeholder": "Enter your last name",
        "autocomplete": "family-name",
    }))
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        "class": "form-control form-control-lg rounded-3",
        "placeholder": "Enter your email",
        "autocomplete": "email",
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control form-control-lg rounded-3",
        "placeholder": "Create a password",
        "autocomplete": "new-password",
    }))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control form-control-lg rounded-3",
        "placeholder": "Repeat your password",
        "autocomplete": "new-password",
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


# === Profile Settings ===
class UserAccountForm(forms.ModelForm):
    """Edit basic User fields."""
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]
        widgets = {
            "first_name": forms.TextInput(attrs={
                "class": "form-control form-control-lg rounded-3",
                "placeholder": "First name"
            }),
            "last_name":  forms.TextInput(attrs={
                "class": "form-control form-control-lg rounded-3",
                "placeholder": "Last name"
            }),
            "email":      forms.EmailInput(attrs={
                "class": "form-control form-control-lg rounded-3",
                "placeholder": "Email"
            }),
        }

    def clean_email(self):
        email = (self.cleaned_data.get("email") or "").strip()
        qs = User.objects.filter(email__iexact=email).exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError("This email is already in use.")
        return email


class AvatarForm(forms.ModelForm):
    """Upload/remove avatar image."""
    remove_avatar = forms.BooleanField(required=False, widget=forms.CheckboxInput(attrs={
        "class": "form-check-input"
    }))

    class Meta:
        model = UserProfile
        fields = ["avatar"]
        widgets = {
            "avatar": forms.ClearableFileInput(attrs={
                "class": "form-control form-control-lg rounded-3",
                "accept": "image/*"
            })
        }

    def clean_avatar(self):
        f = self.cleaned_data.get("avatar")
        if not f:
            return f
        if getattr(f, "size", 0) > 5 * 1024 * 1024:  # 5MB
            raise forms.ValidationError("Avatar is too large (max 5MB).")
        return f


class StyledPasswordChangeForm(PasswordChangeForm):
    """PasswordChangeForm with Bootstrap-friendly widgets."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        placeholders = {
            'old_password': 'Current password',
            'new_password1': 'New password',
            'new_password2': 'Confirm new password',
        }
        for name, field in self.fields.items():
            css = field.widget.attrs.get('class', '')
            field.widget.attrs['class'] = f'{css} form-control form-control-lg rounded-3'.strip()
            if name in placeholders:
                field.widget.attrs.setdefault('placeholder', placeholders[name])
            field.help_text = ''  # hide the long default help text


# ===== CAPSTONE PAPER =======================================================
class CapstonePaperForm(forms.ModelForm):
    """
    Upload/edit form. Category/subcategory/tags are auto-filled by ML in views.
    NOTE: We keep the DB field name `instructor` for compatibility but label it as “Adviser”.
    """
    class Meta:
        model = CapstonePaper
        # status/feedback are intentionally NOT here
        fields = ["title", "abstract", "authors", "file", "publication_year", "instructor"]
        labels = {
            "instructor": "Adviser",
        }
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
            "instructor": forms.TextInput(attrs={"class": "form-control", "placeholder": "Enter adviser name"}),
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

        content_type = (getattr(f, "content_type", "") or "").lower()
        name_ok = f.name.lower().endswith(".pdf")

        # Some servers may not provide content_type on upload; check both
        if (content_type and not content_type.endswith("pdf")) and not name_ok:
            raise forms.ValidationError("Please upload a PDF file.")

        # 20 MB
        if getattr(f, "size", 0) > 20 * 1024 * 1024:
            raise forms.ValidationError("File is too large (max 20MB).")
        return f


# ===== ACCESS REQUEST =======================================================
class PaperAccessRequestForm(forms.ModelForm):
    class Meta:
        model = PaperAccessRequest
        fields = ["reason", "address", "phone"]
        widgets = {
            "reason": forms.Textarea(attrs={
                "class": "form-control",
                "rows": 4,
                "placeholder": "Why do you need access?"
            }),
            "address": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "Address (optional for verified)"
            }),
            "phone": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "Phone (optional for verified)"
            }),
        }

    def clean_phone(self):
        phone = (self.cleaned_data.get("phone") or "").strip()
        if not phone:
            return phone
        # very light validation; allow digits plus + - ( ) and spaces
        if not re.fullmatch(r"[0-9+\-\s()]{7,20}", phone):
            raise ValidationError("Enter a valid phone number.")
        return phone


# === Preferences & Help =====================================================
class PreferencesForm(forms.Form):
    THEME_CHOICES = [
        ("system", "System default"),
        ("light", "Light"),
        ("dark", "Dark"),
    ]
    DENSITY_CHOICES = [
        ("comfortable", "Comfortable"),
        ("compact", "Compact"),
    ]

    theme = forms.ChoiceField(
        choices=THEME_CHOICES,
        initial="system",
        widget=forms.Select(attrs={"class": "form-select form-select-lg rounded-3"})
    )
    ui_density = forms.ChoiceField(
        label="Interface density",
        choices=DENSITY_CHOICES,
        initial="comfortable",
        widget=forms.Select(attrs={"class": "form-select form-select-lg rounded-3"})
    )
    email_opt_in = forms.BooleanField(
        label="Email me updates about my requests",
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"})
    )


class SupportForm(forms.Form):
    subject = forms.CharField(
        widget=forms.TextInput(attrs={
            "class": "form-control form-control-lg rounded-3",
            "placeholder": "Brief summary (e.g., Unable to view PDF)"
        })
    )
    message = forms.CharField(
        widget=forms.Textarea(attrs={
            "class": "form-control rounded-3",
            "rows": 5,
            "placeholder": "Describe the issue or question. Include any steps to reproduce."
        })
    )
    page = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            "class": "form-control rounded-3",
            "placeholder": "Optional: affected page URL or name"
        })
    )
