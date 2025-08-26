from django.urls import path
from account.views import RegisterApiView, LoginApiView, UserProfileView, ChangePasswordView

urlpatterns = [
    path('register/', RegisterApiView.as_view(), name='register'),
    path('login/', LoginApiView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('change_password/', ChangePasswordView.as_view(), name='change_password'),
]