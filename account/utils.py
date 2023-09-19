from django.core.mail import send_mail


def send_activation_code(email, activation_code):
    message = f'''
    Вы успешно зарегистрировались на нашем сайте. Пройдите активацию аккаунта, отправив нам этот код: {activation_code}
    '''

    send_mail(
        'Активация аккаунта',
        message,
        'test@gmail.com',
        [email]
    )

def send_password(email, password):
    message = f'''
    Вот ваш пароль, больше не забывайте! {password}
    '''

    send_mail(
        'Забытый пароль',
        message,
        'test@gmail.com',
        [email]
    )