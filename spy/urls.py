from django.urls import path
from django.contrib.auth.views import LogoutView
from . import views

app_name = 'spy'

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('verify-email/<str:email>/', views.verify_email, name='verify_email'),
    path('', views.index_view, name='index'),# 기본 홈 페이지
    path('index/', views.index_view, name = 'index'),
    path('search/', views.search_view, name='search'),
    path('web/', views.web_shellcodes, name='web_shellcodes'),
    path('linux/', views.linux_shellcodes, name='linux_shellcodes'),
    path('windows/', views.windows_shellcodes, name='windows_shellcodes'),
    path('logout/', LogoutView.as_view(next_page='spy:login'), name='logout'),
    ######################################
    path('analyze/web/<int:shellcode_id>/', views.analyze_web_shellcode, name='analyze_web_shellcode'),
    path('analyze/linux/<int:shellcode_id>/', views.analyze_linux_shellcode, name='analyze_linux_shellcode'),
    path('analyze/windows/<int:shellcode_id>/', views.analyze_windows_shellcode, name='analyze_windows_shellcode'),
]