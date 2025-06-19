import smtplib
from email.mime.text import MIMEText

smtp_server = 'smtp.gmail.com'
smtp_port = 587
smtp_user = 'waynejunj@gmail.com'
smtp_password = 'jsml ywkw tizi mlex'

msg = MIMEText('Test email')
msg['Subject'] = 'Test'
msg['From'] = smtp_user
msg['To'] = 'test@example.com'

try:
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
    print('Email sent successfully')
except Exception as e:
    print(f'Failed to send email: {str(e)}')
