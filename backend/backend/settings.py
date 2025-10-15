from pathlib import Path
import os
import socket
import dj_database_url
from dotenv import load_dotenv

# ===== Base setup =====
BASE_DIR = Path(__file__).resolve().parent.parent  # points to /backend
load_dotenv(BASE_DIR / ".env")

# ===== Security =====
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-key")
DEBUG = os.getenv("DEBUG", "False") == "True"

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "capstonevault.onrender.com"]
CSRF_TRUSTED_ORIGINS = ["https://capstonevault.onrender.com"]

# ===== Installed apps =====
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "whitenoise.runserver_nostatic",
    "widget_tweaks",
    "core",
    "colorfield",
]

# ===== Middleware =====
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",  # must be right after SecurityMiddleware
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "core.middleware.NoCacheForAuthMiddleware",
]

# ===== URL / WSGI =====
ROOT_URLCONF = "backend.urls"
WSGI_APPLICATION = "backend.wsgi.application"

# ===== Templates =====
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "core" / "templates"],  # /backend/core/templates
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ===== Database (auto-switch between local & Render) =====
LOCAL_DB_URL = "postgresql://postgres:1234@localhost:5432/capstonevault_db"
RENDER_DB_URL = os.getenv("DATABASE_URL")

if RENDER_DB_URL:
    print("🔗 Using Render PostgreSQL database.")
    DATABASES = {
        "default": dj_database_url.config(
            default=RENDER_DB_URL, conn_max_age=600, ssl_require=True
        )
    }
else:
    print("💾 Using local PostgreSQL database.")
    DATABASES = {"default": dj_database_url.config(default=LOCAL_DB_URL)}

# ===== Static and Media =====
# Since manage.py is inside /backend, BASE_DIR = /backend
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "core" / "static"]  # points to /backend/core/static
STATIC_ROOT = BASE_DIR / "staticfiles"            # /backend/staticfiles (auto-created)

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# WhiteNoise - enable compressed static files for production
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# ===== Email Configuration =====
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL")

# ===== Other settings =====
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Manila"
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
