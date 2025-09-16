from app import db, User

def reset_admin_password():
    email = "admin@craftghana.local"
    new_password = input("Enter new admin password: ").strip()

    admin = User.query.filter_by(email=email).first()
    if not admin:
        print("⚠️ Admin user not found. Did you seed the database?")
        return

    admin.set_password(new_password)
    db.session.commit()
    print(f"✅ Admin password for {email} has been reset!")

if __name__ == "__main__":
    reset_admin_password()
