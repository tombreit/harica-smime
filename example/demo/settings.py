"""Minimal Django settings for the harica-smime demo.

Everything that a non-persistent single-page demo doesn't need has been
stripped: no database, no auth, no sessions, no admin. The only moving parts
are the CSRF protection (the POST needs it) and the staticfiles app (which
discovers the JS assets shipped by ``harica_smime.contrib.django``).
"""

from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DEBUG = True
SECRET_KEY = "demo-insecure-key-do-not-use-in-production"  # noqa: S105
ALLOWED_HOSTS = ["*"]

ROOT_URLCONF = "demo.urls"

INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "harica_smime.contrib.django",
    "demo",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

DATABASES: dict[str, dict[str, str]] = {}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.csrf",
            ],
        },
    },
]

STATIC_URL = "/static/"

USE_TZ = True
