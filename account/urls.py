from django.urls import path
from .views import *
from django.urls import path
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('register/', RegistrationView.as_view()),
    path('activate/', ActivationView.as_view()),
    path('login/', LoginView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('change_password/', ChangePasswordView.as_view()),
    path('delete_account/', DeleteAccountView.as_view()),
    path('admin_delete_user/', AdminDeleteUserView.as_view()),
    path('upload_avatar/', AvatarUploadView.as_view()),
]

