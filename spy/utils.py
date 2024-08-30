import random
import string
from django.core.mail import send_mail
import openai 
from django.conf import settings

def generate_auth_code():
    characters = string.ascii_letters + string.digits + '@!#$%^'
    return ''.join(random.choice(characters) for _ in range(8))

def send_auth_email(email, auth_code):
    subject = '로그인 인증 코드'
    message = f'귀하의 인증 코드는 {auth_code}입니다. 이 코드를 입력하여 로그인을 완료해주세요.'
    from_email = 'pss3901@gmail.com'
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)

###############################
openai.api_key = settings.OPENAI_API_KEY

def spy_shellcode_with_openai(shellcode):
    try:
        prompt = (
            f"Analyze the following shellcode:\n\n{shellcode}\n\n"
            "Provide the assembly equivalent, the OS it is compatible with, "
            "and the minimum OS version required."
        )

        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=150,
            n=1,
            stop=None,
            temperature=0.5,
        )

        result = response.choices[0].text.strip()
        return result
    
    except Exception as e:
        return str(e)



