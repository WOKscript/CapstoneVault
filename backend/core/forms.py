from django import forms
from django.contrib.auth.models import User
import re

from .models import CapstonePaper, PaperAccessRequest

# ========== LOGIN FORM (email + password only) ==========
class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'class': 'form-control',
        'placeholder': 'Enter your email'
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control',
        'placeholder': 'Enter your password'
    }))


# ========== SIGNUP FORM (first_name, last_name, email, password) ==========
class SignupForm(forms.ModelForm):
    first_name = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Enter your first name'
    }))
    last_name = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Enter your last name'
    }))
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'class': 'form-control',
        'placeholder': 'Enter your email'
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control',
        'placeholder': 'Create a password'
    }))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control',
        'placeholder': 'Repeat your password'
    }))

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password']

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email is already registered.")
        return email

    def clean_password(self):
        password = self.cleaned_data.get("password")
        if len(password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', password):
            raise forms.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            raise forms.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'[0-9]', password):
            raise forms.ValidationError("Password must contain at least one number.")
        if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
            raise forms.ValidationError("Password must contain at least one special character.")
        return password

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm = cleaned_data.get("confirm_password")
        if password and confirm and password != confirm:
            self.add_error('confirm_password', "Passwords do not match")


# ========== CAPSTONE PAPER FORM ==========
class CapstonePaperForm(forms.ModelForm):
    class Meta:
        model = CapstonePaper
        fields = ['title', 'abstract', 'authors', 'file', 'publication_year', 'adviser']

        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter title'}),
            'abstract': forms.Textarea(attrs={
                'class': 'form-control',
                'style': 'height: 150px; resize: none;',
                'placeholder': 'Enter abstract here...'
            }),
            'authors': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter authors'}),
            'file': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'publication_year': forms.NumberInput(attrs={
                'class': 'form-control no-spinner',
                'placeholder': 'e.g. 2023'
            }),
            'adviser': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter adviser name'}),
        }


# ========== PAPER ACCESS REQUEST FORM ==========
class PaperAccessRequestForm(forms.ModelForm):
    class Meta:
        model = PaperAccessRequest
        fields = ['reason', 'address', 'phone']

        widgets = {
            'reason': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'address': forms.TextInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
        }


# ========== REJECTION FEEDBACK FORM ==========
class RejectionFeedbackForm(forms.Form):
    feedback = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        label="Reason for Revision",
        max_length=1000
    )
