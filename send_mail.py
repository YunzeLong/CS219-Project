import smtplib
from email.mime.text import MIMEText

def send_mail(sender, sender_pswd, receiver):
    try:
        s = smtplib.SMTP('smtp.gmail.com',587)
        s.starttls()
        s.login(sender,sender_pswd)

        message = MIMEText('Please change your key.')
        message['Subject'] = '[Warning] Your key is corrupted'
        message['From'] = sender
        message['To'] = receiver

        s.send_message(message)
        s.quit()
        print("Successfully sent!")
    except Exception:
        print("Error: unable to send email")

if __name__ == '__main__':
    sender = "lora.cs219@gmail.com"
    sender_pswd = "rnppboitedgdxgbk"
    receiver = "lora.cs219@gmail.com"
    send_mail(sender,sender_pswd,receiver)