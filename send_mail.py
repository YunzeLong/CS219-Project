import smtplib

def send_mail(sender, sender_pswd, receiver):
    try:
        s = smtplib.SMTP('smtp.gmail.com',587)
        s.starttls()
        s.login(sender,sender_pswd)
        message = """\
        # Subject: test test\
        guns, lots of guns"""

        s.sendmail(sender,receiver,msg=message)
        s.quit()
        print("Successfully sent!")
    except Exception:
        print("Error: unable to send email")

if __name__ == '__main__':
    sender = "lora.cs219@gmail.com"
    sender_pswd = "rnppboitedgdxgbk"
    receiver = "lora.cs219@gmail.com"
    send_mail(sender,sender_pswd,receiver)