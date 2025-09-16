# reset_user.py
from getpass import getpass
from app import db, User, app

with app.app_context():
    email = input("Enter the user's email to reset password: ").strip().lower()
    user = User.query.filter_by(email=email).first()

    if not user:
        print(f"❌ No user found with email: {email}")
    else:
        new_pw = getpass("Enter new password: ")
        confirm_pw = getpass("Confirm new password: ")

        if new_pw != confirm_pw:
            print("❌ Passwords do not match. Try again.")
        else:
            user.set_password(new_pw)
            db.session.commit()
            print(f"✅ Password for {user.email} has been reset successfully!")
