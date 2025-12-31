import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings
import pyotp
from dotenv import load_dotenv
import os

load_dotenv()

BASE_URL = os.getenv("BASE_URL")
RESET_PASSWORD_URL = os.getenv("RESET_PASSWORD_URL")


def generate_OTP():
    otp = pyotp.TOTP(pyotp.random_base32(), digits=4, interval=120)
    return otp.now()


def isemail(email):
    return "@gmail.com" in email


def sendOTP(email, username, otp):
    subject = "Verify Email via OTP"
    body = f"""
    Hello {username},
    
    Thank you for registering! Please use the following OTP to verify your email:
    
    OTP: {otp}
    
    This OTP is valid for 60 seconds.
    
    If you didn't create an account, please ignore this email.
    
    Best regards,
    Dallas
    """

    sender_email = settings.EMAIL_HOST_USER
    sender_password = settings.EMAIL_HOST_PASSWORD

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = email
    message["subject"] = subject

    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
        return True
    except Exception as e:
        return False


def sentLink(email, username, token):

    login_link = BASE_URL + str(token.access_token)
    reset_link = RESET_PASSWORD_URL + str(token.access_token)

    subject = "Verify Email via OTP"
    body = f"""
    Hello {username},
    
    Sorry to hear you are having problem while logging in. Please use the following link to login to Dallas:
    
    login Link: {login_link}

    or if you wish to reset your password please use the following

    Reset password Link: {reset_link}
    
    This link is valid for 60 seconds.
    
    If you didn't opt for forgot password, please ignore this email.
    
    Best regards,
    Dallas
    """

    sender_email = settings.EMAIL_HOST_USER
    sender_password = settings.EMAIL_HOST_PASSWORD

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = email
    message["subject"] = subject

    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
        return True
    except Exception as e:
        return False
