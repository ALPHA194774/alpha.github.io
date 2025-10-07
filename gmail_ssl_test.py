import smtplib
import os
from dotenv import load_dotenv

load_dotenv()

MAIL_SERVER = os.getenv("MAIL_SERVER")
MAIL_PORT = 465
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_FROM = os.getenv("MAIL_FROM")
MAIL_TO = "manueleugen09@gmail.com"

print("🔹 Attempting SSL connection to Gmail...")

try:
    server = smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT)
    server.login(MAIL_USERNAME, MAIL_PASSWORD)
    print("✅ Connected and logged in successfully (SSL)!")

    subject = "SSL Test Email"
    body = "This is a test email via Gmail SSL (port 465)."
    message = f"Subject: {subject}\n\n{body}"

    server.sendmail(MAIL_FROM, MAIL_TO, message)
    print("✅ Test email sent successfully!")

    server.quit()
except Exception as e:
    print("❌ Failed:", e)
