import json
import urllib
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, get_user_model, logout
from django.contrib import messages
from django.core.cache import cache
from django.contrib.auth import login, get_user_model
from .models import WebShellcode, LinuxShellcode, WindowsShellcode
from .documents import WebShellcodeDocument, LinuxShellcodeDocument, WindowsShellcodeDocument
from .utils import generate_auth_code, send_auth_email,spy_shellcode_with_openai
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import MultiMatch


User = get_user_model()

def login_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = authenticate(request, email=email, password=password)
        if user is not None:
            auth_code = generate_auth_code()
            cache.set(f'auth_code_{email}', auth_code, 300)  # 5분 동안 유효
            send_auth_email(email, auth_code)
            return redirect('spy:verify_email', email=email)
        else:
            messages.error(request, '이메일 또는 비밀번호가 올바르지 않습니다.')
    return render(request, 'login.html')

def verify_email(request, email):
    if request.method == 'POST':
        user_input = request.POST['auth_code']
        recaptcha_response = request.POST.get('g-recaptcha-response')
        
        # reCAPTCHA 검증
        url = 'https://www.google.com/recaptcha/api/siteverify'
        values = {
            'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        data = urllib.parse.urlencode(values).encode()
        req = urllib.request.Request(url, data=data)
        response = urllib.request.urlopen(req)
        result = json.loads(response.read().decode())
        
        if result['success']:
            stored_code = cache.get(f'auth_code_{email}')
            if user_input == stored_code:
                try:
                    user = User.objects.get(email=email)
                    login(request, user)
                    cache.delete(f'auth_code_{email}')
                    messages.success(request, '이메일 인증이 완료되었습니다.')
                    return redirect(settings.LOGIN_REDIRECT_URL)
                except User.DoesNotExist:
                    messages.error(request, '사용자를 찾을 수 없습니다.')
            else:
                messages.error(request, '인증 코드가 올바르지 않습니다.')
        else:
            messages.error(request, 'reCAPTCHA 검증에 실패했습니다. 다시 시도해주세요.')
    
    return render(request, 'verify_email.html', {
        'email': email,
        'GOOGLE_RECAPTCHA_SITE_KEY': settings.GOOGLE_RECAPTCHA_SITE_KEY
    })

def register_view(request):
    if request.method == 'POST':
        username = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        # reCAPTCHA 검증
        recaptcha_response = request.POST.get('g-recaptcha-response')
        url = 'https://www.google.com/recaptcha/api/siteverify'
        values = {
            'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        data = urllib.parse.urlencode(values).encode()
        req = urllib.request.Request(url, data=data)
        response = urllib.request.urlopen(req)
        result = json.loads(response.read().decode())
        
        if not result['success']:
            messages.error(request, 'reCAPTCHA 검증에 실패했습니다. 다시 시도해주세요.')
            return render(request, 'register.html')

        if password != confirm_password:
            messages.error(request, '비밀번호가 일치하지 않습니다.')
            return render(request, 'register.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, '이미 사용 중인 이메일입니다.')
            return render(request, 'register.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, '이미 사용 중인 사용자 이름입니다.')
            return render(request, 'register.html')

        # CustomUser 모델을 사용하여 사용자 생성
        user = User.objects.create_user(email=email, username=username, password=password)
        user.save()

        # 성공 메시지 추가
        messages.success(request, '회원가입이 완료되었습니다. 로그인해주세요.')
        
        # 로그인 페이지로 리다이렉트
        return redirect('spy:login')

    return render(request, 'register.html', {'GOOGLE_RECAPTCHA_SITE_KEY': settings.GOOGLE_RECAPTCHA_SITE_KEY})

@login_required(login_url='login')
def index_view(request):
    web_shellcodes = WebShellcodeDocument.search()[:5]
    linux_shellcodes = LinuxShellcodeDocument.search()[:5]
    windows_shellcodes = WindowsShellcodeDocument.search()[:5]
    context = {
        'web_shellcodes': web_shellcodes,
        'linux_shellcodes': linux_shellcodes,
        'windows_shellcodes': windows_shellcodes,
    }
    return render(request, 'index.html', context)

@login_required(login_url='login')
def web_shellcodes(request):
    search_query = request.GET.get('q', '')
    if search_query:
        results = WebShellcodeDocument.search().query("match", content=search_query)
    else:
        results = WebShellcodeDocument.search()
    return render(request, 'web_shellcodes.html', {'results': results})

@login_required(login_url='login')
def linux_shellcodes(request):
    search_query = request.GET.get('q', '')
    if search_query:
        results = LinuxShellcodeDocument.search().query("match", content=search_query)
    else:
        results = LinuxShellcodeDocument.search()
    return render(request, 'linux_shellcodes.html', {'results': results})

@login_required(login_url='login')
def windows_shellcodes(request):
    search_query = request.GET.get('q', '')
    if search_query:
        results = WindowsShellcodeDocument.search().query("match", content=search_query)
    else:
        results = WindowsShellcodeDocument.search()
    return render(request, 'windows_shellcodes.html', {'results': results})

def search_view(request):
    query = request.GET.get('q', '')
    if query:
        s = Search(index=['web_index', 'linux_index', 'windows_index'])
        q = MultiMatch(query=query, fields=['title', 'content'])
        s = s.query(q)
        response = s.execute()
        results = response.hits
    else:
        results = []
    
    return render(request, 'search_results.html', {'results': results, 'query': query})


def logout_view(request):
    logout(request)
    return redirect('spy:login')

######################
def analyze_web_shellcode(request, shellcode_id):
    # shellcode 객체를 데이터베이스에서 가져옵니다.
    shellcode = get_object_or_404(WebShellcode, id=shellcode_id)
    
    # shellcode.analysis_result가 비어 있는지 확인 후 OpenAI API를 사용해 분석합니다.
    if not shellcode.analysis_result:
        shellcode.analysis_result = spy_shellcode_with_openai(shellcode.content)
        shellcode.save()
    
    # 결과를 렌더링하여 템플릿에 전달합니다.
    return render(request, 'analysis_result.html', {'result': shellcode.analysis_result})
# 밑에 내용 똑같음
def analyze_linux_shellcode(request, shellcode_id):
    shellcode = get_object_or_404(LinuxShellcode, id=shellcode_id)
    if not shellcode.analysis_result:
        shellcode.analysis_result = spy_shellcode_with_openai(shellcode.content)
        shellcode.save()
    return render(request, 'analysis_result.html', {'result': shellcode.analysis_result})

def analyze_windows_shellcode(request, shellcode_id):
    shellcode = get_object_or_404(WindowsShellcode, id=shellcode_id)
    if not shellcode.analysis_result:
        shellcode.analysis_result = spy_shellcode_with_openai(shellcode.content)
        shellcode.save()
    return render(request, 'analysis_result.html', {'result': shellcode.analysis_result})