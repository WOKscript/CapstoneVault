# ============================
# core/urls.py
# ============================
from django.urls import path
from django.shortcuts import redirect
from . import views

urlpatterns = [
    # Auth
    path('login/',  views.login_view,  name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('signup/', views.signup_view, name='signup'),

    # Optional: redirect root to login
    path('', lambda req: redirect('login'), name='root-redirect'),

    # Dashboards
    path('dashboard/admin/',         views.admin_dashboard,        name='admin_dashboard'),
    path('dashboard/instructor/',    views.instructor_dashboard,   name='instructor_dashboard'),
    path('dashboard/verified/',      views.verified_dashboard,     name='verified_dashboard'),
    path('dashboard/non-verified/',  views.non_verified_dashboard, name='non_verified_dashboard'),

    # Paper upload & listing
    path('upload/',                         views.upload_paper_view,           name='upload_capstone'),
    path('capstones/',                      views.capstones_main_view,         name='capstones_main'),
    path('capstones/<slug:category>/',      views.capstone_list_by_category,   name='capstones_by_category'),
    path('capstone/<int:paper_id>/edit/',   views.edit_paper_view,             name='edit_paper'),
    path('capstone/<int:paper_id>/delete/', views.delete_paper_view,           name='delete_paper'),

    # Cancel revision (new)
    path('capstone/<int:paper_id>/cancel/', views.cancel_revision,             name='cancel_revision'),

    # Secure PDF viewing
    path('papers/<int:paper_id>/view/',     views.view_paper,                  name='view_paper'),
    path('papers/<int:paper_id>/pdf/',      views.serve_secure_pdf,            name='serve_secure_pdf'),

    # Debug watermark function (REMOVE IN PRODUCTION)
    path('debug-watermark/<int:paper_id>/', views.debug_watermark_test,        name='debug_watermark_test'),

    # Upload-access management (Instructor)
    path('instructor/manage-upload-access/',         views.manage_upload_access,   name='manage_upload_access'),
    path('instructor/toggle-upload/<int:user_id>/',  views.toggle_upload_access,   name='toggle_upload_access'),

    # Access requests
    path('request-access/<int:paper_id>/',         views.request_access_view,     name='request_access'),
    path('requests/',                              views.access_request_list,     name='access_request_list'),
    path('requests/<int:request_id>/approve/',     views.approve_access_request,  name='approve_access_request'),
    path('requests/<int:request_id>/reject/',      views.reject_access_request,   name='reject_access_request'),

    # Trends Visualization Dashboard + APIs
    path('trends/',                   views.trends_dashboard,   name='trends_dashboard'),
    path('api/trends/',               views.trends_api,         name='trends_api'),
    path('api/trends/most-accessed/', views.most_accessed_api,  name='most_accessed_api'),
]