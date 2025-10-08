# core/urls.py
from django.urls import path
from django.shortcuts import redirect
from . import views
from django.urls import path, reverse_lazy
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('login/',  views.login_view,  name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('signup/', views.signup_view, name='signup'),

    path('', lambda req: redirect('login'), name='root-redirect'),

    path('dashboard/admin/',         views.admin_dashboard,        name='admin_dashboard'),
    path('dashboard/instructor/',    views.instructor_dashboard,   name='instructor_dashboard'),
    path('dashboard/verified/',      views.verified_dashboard,     name='verified_dashboard'),
    path('dashboard/non-verified/',  views.non_verified_dashboard, name='non_verified_dashboard'),

    path('users/',                       views.user_management_view,  name='user_management'),
    path('users/create/',                views.create_user_view,      name='create_user'),
    path('users/<int:user_id>/edit/',    views.edit_user_view,        name='edit_user'),
    path('users/<int:user_id>/delete/',  views.delete_user_view,      name='delete_user'),
    path('users/<int:user_id>/toggle/',  views.toggle_user_status,    name='toggle_user_status'),
    path('users/<int:user_id>/reset-password/', views.reset_user_password, name='reset_user_password'),

    path('upload/',                         views.upload_paper_view,           name='upload_capstone'),
    path('capstones/',                      views.capstones_main_view,         name='capstones_main'),
    path('capstones/<slug:category>/',      views.capstone_list_by_category,   name='capstones_by_category'),
    path('capstone/<int:paper_id>/edit/',   views.edit_paper_view,             name='edit_paper'),
    path('capstone/<int:paper_id>/delete/', views.delete_paper_view,           name='delete_paper'),
    path('capstone/<int:paper_id>/cancel/', views.cancel_revision,             name='cancel_revision'),

    path('papers/<int:paper_id>/view/',     views.view_paper,                  name='view_paper'),
    path('papers/<int:paper_id>/pdf/',      views.serve_secure_pdf,            name='serve_secure_pdf'),

    path('debug-watermark/<int:paper_id>/', views.debug_watermark_test,        name='debug_watermark_test'),

    path('instructor/manage-upload-access/',         views.manage_upload_access,   name='manage_upload_access'),
    path('instructor/toggle-upload/<int:user_id>/',  views.toggle_upload_access,   name='toggle_upload_access'),

    path('request-access/<int:paper_id>/',         views.request_access_view,     name='request_access'),
    path('requests/',                              views.access_request_list,     name='access_request_list'),
    path('requests/<int:request_id>/approve/',     views.approve_access_request,  name='approve_access_request'),
    path('requests/<int:request_id>/reject/',      views.reject_access_request,   name='reject_access_request'),

    path('trends/',                    views.trends_dashboard,   name='trends_dashboard'),
    path('api/trends/',                views.trends_api,         name='trends_api'),
    path('api/trends/most-accessed/', views.most_accessed_api,  name='most_accessed_api'),

    path('audit-logs/',                 views.audit_logs_view,   name='audit_logs'),
    path('audit-logs/<int:log_id>/',   views.audit_log_detail,  name='audit_log_detail'),
    
    path('settings/profile/', views.profile_settings, name='profile_settings'),
    
    path("settings/preferences/", views.preferences_view, name="preferences"),
    path("settings/help/", views.help_support_view, name="help_support"),
    
     path(
        "auth/password-reset/",
        auth_views.PasswordResetView.as_view(
            template_name="core/password_reset.html",
            email_template_name="core/password_reset_email.txt",
            subject_template_name="core/password_reset_subject.txt",
            success_url=reverse_lazy("password_reset_done"),
        ),
        name="password_reset",
    ),

    # Password reset (email sent)
    path(
        "auth/password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="core/password_reset_done.html"
        ),
        name="password_reset_done",
    ),

    # Password reset (confirm via link)
    path(
        "auth/reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="core/password_reset_confirm.html",
            success_url=reverse_lazy("password_reset_complete"),
        ),
        name="password_reset_confirm",
    ),

    # Password reset (complete)
    path(
        "auth/reset/complete/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="core/password_reset_complete.html"
        ),
        name="password_reset_complete",
    ),
    
]
