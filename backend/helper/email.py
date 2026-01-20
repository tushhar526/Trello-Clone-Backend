from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from dotenv import load_dotenv
import os
from django.conf import settings

load_dotenv()

BASE_URL = os.getenv("BASE_URL")
RESET_PASSWORD_URL = os.getenv("RESET_PASSWORD_URL")


def sendOTP(email, username, otp):
    subject = "Verify Email via OTP"
    body = f"""
    Hello {username},
    
    Thank you for registering! Please use the following OTP to verify your email:
    
    OTP: {otp}
    
    This OTP is valid for 5 minutes.
    
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

    login_link = BASE_URL + str(token)
    reset_link = RESET_PASSWORD_URL + str(token)

    subject = f""" {username} , we've made it easy to get back on Dallas"""
    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f6f8; padding: 20px;">
        <div style="max-width: 500px; margin: auto; background: #ffffff; padding: 20px; border-radius: 8px;">
        
        <h2 style="color: #333;">Hello {username},</h2>

        <p>
            Sorry to hear you're having trouble logging in.
            Click the button below to continue.
        </p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{login_link}"
            style="
                background-color: #4f46e5;
                color: #ffffff;
                padding: 12px 20px;
                text-decoration: none;
                border-radius: 6px;
                font-weight: bold;
                display: inline-block;
            ">
            Log in to Dallas
            </a>
        </div>

        <p>
            Or reset your password using the link below:
        </p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_link}"
            style="
                background-color: #4f46e5;
                color: #ffffff;
                padding: 12px 20px;
                text-decoration: none;
                border-radius: 6px;
                font-weight: bold;
                display: inline-block;
            ">
            Reset Your Password
            </a>
        </div>

        <p style="color: #666; font-size: 12px;">
            This link is valid for 2 minutes.<br>
            If you didn’t request this, you can safely ignore this email.
        </p>

        <p>— Dallas Team</p>

        </div>
    </body>
    </html>
    """

    sender_email = settings.EMAIL_HOST_USER
    sender_password = settings.EMAIL_HOST_PASSWORD

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = email
    message["subject"] = subject

    message.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
        return True
    except Exception as e:
        return False


def sendInvite(email, reciever, token, workspace_name,sender):
    invite_link = BASE_URL + str(token)

    subject = f""" {reciever} , You have been invited to {workspace_name}"""
    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f6f8; padding: 20px;">
        <div style="max-width: 500px; margin: auto; background: #ffffff; padding: 20px; border-radius: 8px;">
        
        <h2 style="color: #333;">Hello {reciever},</h2>

        <p>
            You have been invited to the {workspace_name} by {sender} 
        </p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{invite_link}"
            style="
                background-color: #4f46e5;
                color: #ffffff;
                padding: 12px 20px;
                text-decoration: none;
                border-radius: 6px;
                font-weight: bold;
                display: inline-block;
            ">
            Be a part of this workspace
            </a>
        </div>

        <p style="color: #666; font-size: 12px;">
            This link is valid for 5 minutes.<br>
            Ignore this mail if you don't to join this workspace
        </p>

        <p>— Dallas Team</p>

        </div>
    </body>
    </html>
    """

    sender_email = settings.EMAIL_HOST_USER
    sender_password = settings.EMAIL_HOST_PASSWORD

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = email
    message["subject"] = subject

    message.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
        return True
    except Exception as e:
        return False
