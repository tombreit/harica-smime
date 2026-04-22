from __future__ import annotations

from django.urls import path

from demo import views

urlpatterns = [
    path("", views.index, name="index"),
    path("submit-csr/", views.submit_csr, name="submit-csr"),
]
