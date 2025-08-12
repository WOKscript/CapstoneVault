# ============================
# core/urls.py  (FULL FILE)
# ============================
from django.urls import path
from django.shortcuts import redirect

from .views import (
    login_view, logout_view, signup_view,
    admin_dashboard, adviser_dashboard,
    verified_dashboard, non_verified_dashboard,
    upload_paper_view, capstones_main_view,
    capstone_list_by_category, edit_paper_view,
    delete_paper_view, adviser_pending_papers,
    adviser_approve_paper, adviser_revise_paper,
    manage_upload_access, toggle_upload_access,
    request_access_view, access_request_list,
    approve_access_request, reject_access_request,
    view_paper, trends_dashboard, trends_api,
    most_accessed_api, cancel_revision,
)

urlpatterns = [
    # Auth
    path('login/',  login_view,  name='login'),
    path('logout/', logout_view, name='logout'),
    path('signup/', signup_view, name='signup'),

    # Optional: redirect root to login
    path('', lambda req: redirect('login'), name='root-redirect'),

    # Dashboards
    path('dashboard/admin/',         admin_dashboard,        name='admin_dashboard'),
    path('dashboard/adviser/',       adviser_dashboard,      name='adviser_dashboard'),
    path('dashboard/verified/',      verified_dashboard,     name='verified_dashboard'),
    path('dashboard/non-verified/',  non_verified_dashboard, name='non_verified_dashboard'),

    # Paper upload & listing
    path('upload/',                         upload_paper_view,           name='upload_capstone'),
    path('capstones/',                      capstones_main_view,         name='capstones_main'),
    path('capstones/<slug:category>/',      capstone_list_by_category,   name='capstones_by_category'),
    path('capstone/<int:paper_id>/edit/',   edit_paper_view,             name='edit_paper'),
    path('capstone/<int:paper_id>/delete/', delete_paper_view,           name='delete_paper'),

    # Cancel revision (new)
    path('capstone/<int:paper_id>/cancel/', cancel_revision,             name='cancel_revision'),

    # Watermarked viewing
    path('papers/<int:paper_id>/view/',     view_paper,                  name='view_paper'),

    # Adviser review
    path('adviser/pending/',                      adviser_pending_papers, name='adviser_pending_papers'),
    path('adviser/paper/<int:paper_id>/approve/', adviser_approve_paper, name='adviser_approve_paper'),
    path('adviser/paper/<int:paper_id>/revise/',  adviser_revise_paper,  name='adviser_revise_paper'),

    # Upload-access management
    path('adviser/manage-upload-access/',         manage_upload_access,   name='manage_upload_access'),
    path('adviser/toggle-upload/<int:user_id>/',  toggle_upload_access,   name='toggle_upload_access'),

    # Access requests
    path('request-access/<int:paper_id>/',                request_access_view,     name='request_access'),
    path('requests/',                                     access_request_list,     name='access_request_list'),
    path('requests/<int:request_id>/approve/',            approve_access_request,  name='approve_access_request'),
    path('requests/<int:request_id>/reject/',             reject_access_request,   name='reject_access_request'),

    # Trends Visualization Dashboard + APIs
    path("trends/", trends_dashboard, name="trends_dashboard"),
    path("api/trends/", trends_api, name="trends_api"),
    path("api/trends/most-accessed/", most_accessed_api, name="most_accessed_api"),
]
