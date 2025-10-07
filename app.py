# app.py (cleaned, commented, migration-friendly)
import os
from datetime import datetime
from dotenv import load_dotenv
import logging
logging.basicConfig(level=logging.INFO)

# load .env (safe place for secrets)
load_dotenv()

from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, session, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, MetaData, func

# Optional: Flask-Mail; import but configured from env
from flask_mail import Mail, Message
app = Flask(__name__, static_folder='static', template_folder='templates', instance_relative_config=True)


# ---------- Setup ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)


# Inject current year/time into all templates
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.route("/test-static")
def test_static():
    import os
    full_path = os.path.join(app.static_folder, "images", "about-hero.jpg")
    return f"Exists: {os.path.exists(full_path)}<br>Path: {full_path}"


# ---------- Order status helpers (top-level) ----------
ORDER_STATUSES = ["pending", "processing", "shipped", "delivered", "cancelled"]

@app.context_processor
def inject_order_helpers():
    """
    Helpers available to all templates:
    - status_badge(status) -> bootstrap badge color
    - ORDER_STATUSES -> list of allowed statuses for selects
    """
    def status_badge(status):
        cls = {
            "pending": "secondary",
            "processing": "info",
            "shipped": "primary",
            "delivered": "success",
            "cancelled": "danger"
        }
        return cls.get(status, "secondary")
    return dict(status_badge=status_badge, ORDER_STATUSES=ORDER_STATUSES)
# -------------------------------------------------------------------------------------

# Basic config (use env vars where possible)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# Force absolute path for SQLite DB to avoid "unable to open database file"
db_path = os.path.abspath(os.path.join(BASE_DIR, "instance", "craftghana.db"))
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ----- Temporary Hardcoded Mail Config for SSL Test -----
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = "manueleugen09@gmail.com"
app.config["MAIL_PASSWORD"] = "oirkpruwmwcjecam"  # your Gmail App Password
app.config["MAIL_DEFAULT_SENDER"] = "manueleugen09@gmail.com"
# --------------------------------------------------------


mail = Mail(app)  # safe to call even if not configured

# Alembic naming convention (helps with migrations)
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}
metadata = MetaData(naming_convention=convention)

db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ---------- Models ----------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="customer")  # customer, artisan, admin

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(140), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    image_filename = db.Column(db.String(255), nullable=True)  # primary image / fallback
    quantity = db.Column(db.Integer, nullable=False, default=1)
    artisan_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    artisan = db.relationship("User", backref="items")

class ItemImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("item.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)

    item = db.relationship("Item", backref="images")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    total = db.Column(db.Float, nullable=False)
    # server_default ensures existing rows get a default when adding column via migration
    status = db.Column(db.String(30), nullable=False, server_default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    buyer = db.relationship("User", backref="orders")

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("item.id"), nullable=False)
    title = db.Column(db.String(140), nullable=False)
    price = db.Column(db.Float, nullable=False)
    qty = db.Column(db.Integer, nullable=False, default=1)

    order = db.relationship("Order", backref="order_items")
    item = db.relationship("Item")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- Helpers ----------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"png", "jpg", "jpeg", "webp"}

def get_cart():
    return session.get("cart", {})

def save_cart(cart):
    session["cart"] = cart
    session.modified = True

# ---------- Routes ----------
@app.route("/")
def home():
    latest = Item.query.order_by(Item.created_at.desc()).limit(8).all()
    return render_template("home.html", items=latest)

# ---- Create-first-admin route (one-time)
@app.route("/create-admin", methods=["GET", "POST"])
def create_admin_route():
    """
    One-time page to create an admin if none exists.
    After an admin exists this route redirects to login.
    """
    if User.query.filter_by(role="admin").first():
        flash("Admin already exists. This page is disabled.", "info")
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        pw2 = request.form.get("password_confirm", "")

        if not name or not email or not password:
            flash("All fields required", "danger")
            return redirect(url_for("create_admin_route"))
        if password != pw2:
            flash("Passwords do not match", "danger")
            return redirect(url_for("create_admin_route"))
        if User.query.filter_by(email=email).first():
            flash("Email already in use", "danger")
            return redirect(url_for("create_admin_route"))

        user = User(full_name=name, email=email, role="admin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Admin account created. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("create_admin.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("full_name","").strip()
        email = request.form.get("email","").lower().strip()
        password = request.form.get("password","")
        role = request.form.get("role","customer")
        if not name or not email or not password:
            flash("All fields are required", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Email already in use", "danger")
            return redirect(url_for("register"))
        user = User(full_name=name, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("auth_register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").lower().strip()
        password = request.form.get("password","")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Welcome back!", "success")
            if user.role == "artisan":
                return redirect(url_for("artisan_dashboard"))
            if user.role == "admin":
                return redirect(url_for("admin"))
            return redirect(url_for("home"))
        flash("Invalid credentials", "danger")
    return render_template("auth_login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("home"))

# ---- Admin orders management (list + update)
@app.route("/admin/orders")
@login_required
def admin_orders():
    if current_user.role != "admin":
        flash("Admin access only", "danger")
        return redirect(url_for("home"))

    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin_orders.html", orders=orders)

@app.route("/admin/order/<int:order_id>/update_status", methods=["POST"])
@login_required
def admin_update_order_status(order_id):
    if current_user.role != "admin":
        flash("Admin access only", "danger")
        return redirect(url_for("home"))

    order = Order.query.get_or_404(order_id)
    new_status = request.form.get("status")
    if new_status not in ORDER_STATUSES:
        flash("Invalid status", "danger")
        return redirect(url_for("admin_orders"))

    old_status = order.status
    order.status = new_status
    db.session.commit()

    # Optional: notify buyer by email
    if order.buyer and order.buyer.email and app.config.get("MAIL_USERNAME") and app.config.get("MAIL_PASSWORD"):
        try:
            msg = Message(
                f"Order #{order.id} status updated",
                sender=app.config.get("MAIL_USERNAME"),
                recipients=[order.buyer.email]
            )
            msg.body = f"Hello {order.buyer.full_name},\n\nYour order #{order.id} status changed from '{old_status}' to '{new_status}'.\n\nCraftGhana Team"
            mail.send(msg)
        except Exception:
            app.logger.exception("Admin status update email failed")

    flash(f"Order #{order.id} updated to {new_status}", "success")
    return redirect(url_for("admin_orders"))

# ----- Artisan pages -----
@app.route("/artisan")
@login_required
def artisan_dashboard():
    if current_user.role != "artisan":
        flash("Artisan access only", "warning")
        return redirect(url_for("home"))
    my_items = Item.query.filter_by(artisan_id=current_user.id).all()
    return render_template("artisan_dashboard.html", items=my_items)

@app.route("/upload", methods=["GET","POST"])
@login_required
def upload_item():
    if current_user.role != "artisan":
        flash("Artisan access only", "warning")
        return redirect(url_for("home"))

    if request.method == "POST":
        title = request.form.get("title","").strip()
        desc = request.form.get("description","").strip()
        try:
            price = float(request.form.get("price","0") or 0)
        except ValueError:
            price = 0
        category = request.form.get("category","General").strip()
        try:
            qty = int(request.form.get("quantity","1") or 1)
        except ValueError:
            qty = 1

        if not title or not desc or price <= 0:
            flash("Please fill all fields correctly", "danger")
            return redirect(url_for("upload_item"))

        # Create item then save images referencing item.id
        item = Item(title=title, description=desc, price=price,
                    category=category, quantity=qty, artisan_id=current_user.id)
        db.session.add(item)
        db.session.flush()

        # primary image
        prim_file = request.files.get("image")
        if prim_file and allowed_file(prim_file.filename):
            prim_filename = secure_filename(f"{datetime.utcnow().timestamp()}_{prim_file.filename}")
            prim_file.save(os.path.join(app.config["UPLOAD_FOLDER"], prim_filename))
            item.image_filename = prim_filename

        # multiple images (input name="images")
        files = request.files.getlist("images")
        for f in files:
            if f and allowed_file(f.filename):
                filename = secure_filename(f"{datetime.utcnow().timestamp()}_{f.filename}")
                f.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                db.session.add(ItemImage(item_id=item.id, filename=filename))

        db.session.commit()
        flash("Item uploaded!", "success")
        return redirect(url_for("artisan_dashboard"))

    return render_template("upload_item.html")

@app.route("/artisan/edit/<int:item_id>", methods=["GET","POST"])
@login_required
def edit_item(item_id):
    if current_user.role != "artisan":
        flash("Access denied", "danger")
        return redirect(url_for("home"))

    item = Item.query.get_or_404(item_id)
    if item.artisan_id != current_user.id:
        flash("You can only edit your own items", "danger")
        return redirect(url_for("artisan_dashboard"))

    if request.method == "POST":
        title = request.form.get("title","").strip()
        desc = request.form.get("description","").strip()
        try:
            price = float(request.form.get("price","0") or 0)
        except ValueError:
            price = 0
        category = request.form.get("category","General").strip()
        try:
            qty = int(request.form.get("quantity","1") or 1)
        except ValueError:
            qty = 1

        file = request.files.get("image")
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            item.image_filename = filename

        files = request.files.getlist("images")
        for f in files:
            if f and allowed_file(f.filename):
                filename = secure_filename(f"{datetime.utcnow().timestamp()}_{f.filename}")
                f.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                db.session.add(ItemImage(item_id=item.id, filename=filename))

        item.title = title
        item.description = desc
        item.price = price
        item.category = category
        item.quantity = qty

        db.session.commit()
        flash("Item updated successfully", "success")
        return redirect(url_for("artisan_dashboard"))

    return render_template("edit_item.html", item=item)

@app.route("/artisan/delete/<int:item_id>", methods=["GET","POST"])
@login_required
def delete_item(item_id):
    if current_user.role != "artisan":
        flash("Access denied", "danger")
        return redirect(url_for("home"))

    item = Item.query.get_or_404(item_id)
    if item.artisan_id != current_user.id:
        flash("You can only delete your own items", "danger")
        return redirect(url_for("artisan_dashboard"))

    if request.method == "POST":
        # delete images from disk and DB
        for img in list(item.images):
            try:
                path = os.path.join(app.config["UPLOAD_FOLDER"], img.filename)
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
            db.session.delete(img)

        if item.image_filename:
            try:
                p = os.path.join(app.config["UPLOAD_FOLDER"], item.image_filename)
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass

        db.session.delete(item)
        db.session.commit()
        flash("Item deleted successfully", "success")
        return redirect(url_for("artisan_dashboard"))

    return render_template("confirm_delete.html",
                           entity="item",
                           name=item.title,
                           confirm_url=url_for("delete_item", item_id=item.id))

# Artisan: view orders that include their items
@app.route("/artisan/orders")
@login_required
def artisan_orders():
    if current_user.role != "artisan":
        flash("Artisan access only", "warning")
        return redirect(url_for("home"))

    order_items = (db.session.query(OrderItem)
                   .join(Item, OrderItem.item_id == Item.id)
                   .join(Order, OrderItem.order_id == Order.id)
                   .filter(Item.artisan_id == current_user.id)
                   .order_by(Order.created_at.desc())
                   .all())

    orders_map = {}
    for oi in order_items:
        o = oi.order
        if o.id not in orders_map:
            orders_map[o.id] = {"order": o, "items": []}
        orders_map[o.id]["items"].append(oi)

    orders_list = list(orders_map.values())
    return render_template("artisan_orders.html", orders_list=orders_list)

@app.route("/artisan/order/<int:order_id>/update_status", methods=["POST"])
@login_required
def artisan_update_order_status(order_id):
    if current_user.role != "artisan":
        flash("Artisan access only", "warning")
        return redirect(url_for("home"))

    order = Order.query.get_or_404(order_id)

    # confirm artisan has at least one item in the order
    has_item = any(oi.item and oi.item.artisan_id == current_user.id for oi in order.order_items)
    if not has_item:
        flash("You can't change status for orders that don't contain your items", "danger")
        return redirect(url_for("artisan_orders"))

    new_status = request.form.get("status", "pending")
    if new_status not in ORDER_STATUSES:
        flash("Invalid status", "danger")
        return redirect(url_for("artisan_orders"))

    old_status = order.status
    order.status = new_status
    db.session.commit()

    # Notify buyer by email (best-effort)
    if order.buyer and order.buyer.email and app.config.get("MAIL_USERNAME") and app.config.get("MAIL_PASSWORD"):
        try:
            subject = f"Order #{order.id} status updated to {new_status}"
            body = f"Hello {order.buyer.full_name},\n\nThe status for your order #{order.id} has changed from '{old_status}' to '{new_status}'.\n\nThanks,\nCraftGhana"
            msg = Message(subject, sender=app.config.get("MAIL_USERNAME"), recipients=[order.buyer.email])
            msg.body = body
            mail.send(msg)
        except Exception:
            app.logger.exception("Failed to send buyer notification email")

    flash("Order status updated", "success")
    return redirect(url_for("artisan_orders"))

# ----- Browse & Cart -----
@app.route("/browse")
def browse():
    q = request.args.get("q","").strip()
    category = request.args.get("category","")
    query = Item.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Item.title.ilike(like), Item.description.ilike(like)))
    if category:
        query = query.filter_by(category=category)
    items = query.order_by(Item.created_at.desc()).all()
    cats = [c[0] for c in db.session.query(Item.category).distinct().all()]
    return render_template("browse.html", items=items, categories=cats, q=q, selected_category=category)

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/item/<int:item_id>")
def item_detail(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template("item.html", item=item)

@app.route("/cart/add/<int:item_id>")
def cart_add(item_id):
    item = Item.query.get_or_404(item_id)
    cart = get_cart()
    cart[str(item_id)] = cart.get(str(item_id), 0) + 1
    save_cart(cart)
    flash(f"Added {item.title} to cart", "success")
    return redirect(request.referrer or url_for("browse"))

@app.route("/cart")
def cart():
    cart = get_cart()
    item_rows, total = [], 0.0
    for item_id, qty in cart.items():
        item = Item.query.get(int(item_id))
        if item:
            subtotal = item.price * qty
            total += subtotal
            item_rows.append({"item": item, "qty": qty, "subtotal": subtotal})
    return render_template("cart.html", rows=item_rows, total=total)

@app.route("/cart/clear")
def cart_clear():
    save_cart({})
    flash("Cart cleared", "info")
    return redirect(url_for("cart"))

# Checkout (creates Order, OrderItems, notifies buyer and artisans/admins if mail configured)
@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    cart = get_cart()
    if not cart:
        flash("Cart is empty", "warning")
        return redirect(url_for("browse"))

    total = 0.0
    items_to_save = []
    for item_id, qty in cart.items():
        item = Item.query.get(int(item_id))
        if item:
            total += item.price * qty
            items_to_save.append((item, qty))

    order = Order(buyer_id=current_user.id, total=round(total, 2))
    db.session.add(order)
    db.session.flush()

    for item, qty in items_to_save:
        db.session.add(OrderItem(order_id=order.id, item_id=item.id, title=item.title, price=item.price, qty=qty))
        item.quantity = max(0, item.quantity - qty)

    db.session.commit()

    # ====== Email notifications (buyer + artisans + admin) ======
    mail_ok = app.config.get("MAIL_USERNAME") and app.config.get("MAIL_PASSWORD")
    if mail_ok:
        try:
            # Buyer confirmation
            buyer_msg = Message(
                f"Order Confirmation #{order.id}",
                sender=app.config.get("MAIL_DEFAULT_SENDER"),
                recipients=[current_user.email]
            )
            buyer_msg.body = (
                f"Hi {current_user.full_name},\n\nThanks for your order #{order.id}. Total: ₵{order.total:.2f}\n\n"
                f"You can view your orders at: {url_for('my_orders', _external=True)}\n\n— CraftGhana"
            )
            mail.send(buyer_msg)
        except Exception as e:
            app.logger.error(f"Buyer email sending failed for order {order.id}: {e}")

        try:
            # Artisans notifications (unique emails)
            artisan_emails = set()
            for item, qty in items_to_save:
                artisan = item.artisan
                if artisan and artisan.email:
                    artisan_emails.add(artisan.email)

            for email in artisan_emails:
                artisan_msg = Message(
                    f"New Order #{order.id} includes your items",
                    sender=app.config.get("MAIL_DEFAULT_SENDER"),
                    recipients=[email]
                )
                artisan_msg.body = (
                    f"Hello,\n\nOrder #{order.id} contains one or more of your items.\n"
                    f"Please check your Artisan Dashboard: {url_for('artisan_orders', _external=True)}\n\nThanks,\nCraftGhana Team"
                )
                mail.send(artisan_msg)
        except Exception as e:
            app.logger.exception(f"Artisan notification(s) failed for order {order.id}: {e}")

        try:
            # Admin notification (notify all admins)
            admins = User.query.filter_by(role="admin").all()
            admin_emails = [a.email for a in admins if a.email]
            if admin_emails:
                admin_msg = Message(
                    f"New Order #{order.id} placed",
                    sender=app.config.get("MAIL_DEFAULT_SENDER"),
                    recipients=admin_emails
                )
                admin_msg.body = (
                    f"Admin,\n\nOrder #{order.id} was created by {current_user.full_name} ({current_user.email}).\n"
                    f"Total: ₵{order.total:.2f}\n\nView: {url_for('admin_orders', _external=True)}\n\n— CraftGhana"
                )
                mail.send(admin_msg)
        except Exception as e:
            app.logger.exception(f"Admin notification failed for order {order.id}: {e}")
    else:
        app.logger.debug("Mail not configured - skipping email sends")
    # ============================================================

    save_cart({})
    flash(f"Order #{order.id} placed successfully.", "success")
    return redirect(url_for("home"))

# ----- Admin -----
@app.route("/admin")
@login_required
def admin():
    if current_user.role != "admin":
        flash("Admin only", "warning")
        return redirect(url_for("home"))
    users = User.query.order_by(User.id.desc()).all()
    items = Item.query.order_by(Item.created_at.desc()).all()
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin.html", users=users, items=items, orders=orders)

@app.route("/admin/analytics")
@login_required
def admin_analytics():
    if current_user.role != "admin":
        flash("Admin only", "danger")
        return redirect(url_for("home"))

    total_sales = db.session.query(func.sum(Order.total)).scalar() or 0
    top_artisans = (
        db.session.query(User.full_name, func.sum(OrderItem.qty * OrderItem.price).label("revenue"))
        .join(Item, Item.id == OrderItem.item_id)
        .join(User, User.id == Item.artisan_id)
        .group_by(User.id)
        .order_by(func.sum(OrderItem.qty * OrderItem.price).desc())
        .limit(5).all()
    )
    return render_template("admin_analytics.html", total_sales=total_sales, top_artisans=top_artisans)

@app.route("/admin/user/<int:user_id>/edit", methods=["GET","POST"])
@login_required
def edit_user(user_id):
    if current_user.role != "admin":
        flash("Admins only!", "danger")
        return redirect(url_for("home"))
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        user.full_name = request.form["full_name"].strip()
        user.email = request.form["email"].strip().lower()
        user.role = request.form["role"]
        pw = request.form.get("password", "").strip()
        if pw:
            user.set_password(pw)
        db.session.commit()
        flash("User updated successfully", "success")
        return redirect(url_for("admin"))
    return render_template("edit_user.html", user=user)

@app.route("/admin/delete/user/<int:user_id>", methods=["GET","POST"])
@login_required
def admin_delete_user(user_id):
    if current_user.role != "admin":
        flash("Admin only", "danger")
        return redirect(url_for("home"))
    user = User.query.get_or_404(user_id)
    if user.role == "admin":
        flash("Cannot delete another admin", "danger")
        return redirect(url_for("admin"))
    if request.method == "POST":
        db.session.delete(user)
        db.session.commit()
        flash("User deleted", "success")
        return redirect(url_for("admin"))
    return render_template("confirm_delete.html",
                           entity="user",
                           name=user.full_name,
                           confirm_url=url_for("admin_delete_user", user_id=user.id))

@app.route("/admin/delete/item/<int:item_id>", methods=["GET","POST"])
@login_required
def admin_delete_item(item_id):
    if current_user.role != "admin":
        flash("Admin only", "danger")
        return redirect(url_for("home"))
    item = Item.query.get_or_404(item_id)
    if request.method == "POST":
        for img in list(item.images):
            try:
                path = os.path.join(app.config["UPLOAD_FOLDER"], img.filename)
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
            db.session.delete(img)
        if item.image_filename:
            try:
                p = os.path.join(app.config["UPLOAD_FOLDER"], item.image_filename)
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        db.session.delete(item)
        db.session.commit()
        flash("Item deleted", "success")
        return redirect(url_for("admin"))
    return render_template("confirm_delete.html",
                           entity="item",
                           name=item.title,
                           confirm_url=url_for("admin_delete_item", item_id=item.id))

@app.route("/admin/delete/order/<int:order_id>", methods=["GET","POST"])
@login_required
def admin_delete_order(order_id):
    if current_user.role != "admin":
        flash("Admin only", "danger")
        return redirect(url_for("home"))
    order = Order.query.get_or_404(order_id)
    if request.method == "POST":
        db.session.delete(order)
        db.session.commit()
        flash("Order deleted", "success")
        return redirect(url_for("admin"))
    return render_template("confirm_delete.html",
                           entity="order",
                           name=f"Order #{order.id}",
                           confirm_url=url_for("admin_delete_order", order_id=order.id))

@app.route("/admin/user/<int:user_id>/reset_password", methods=["GET","POST"])
@login_required
def admin_reset_password(user_id):
    if current_user.role != "admin":
        flash("Admin only", "danger")
        return redirect(url_for("home"))
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        new_pw = request.form.get("password", "").strip()
        confirm_pw = request.form.get("confirm_password", "").strip()
        if not new_pw:
            flash("Password cannot be empty", "danger")
        elif new_pw != confirm_pw:
            flash("Passwords do not match", "danger")
        else:
            user.set_password(new_pw)
            db.session.commit()
            flash(f"Password for {user.full_name} has been reset successfully", "success")
            return redirect(url_for("admin"))
    return render_template("reset_password.html", user=user)

@app.route("/my_orders")
@login_required
def my_orders():
    orders = Order.query.filter_by(buyer_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template("my_orders.html", orders=orders)

# Serve uploaded images
@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ---------- Utilities / bootstrap ----------
def seed_demo_data():
    """Optional demo seed — disabled by default; keep for dev if desired."""
    if not User.query.filter_by(email="admin@craftghana.local").first():
        admin = User(full_name="Admin User", email="admin@craftghana.local", role="admin")
        admin.set_password("admin123")
        db.session.add(admin)
    if not User.query.filter_by(email="artisan@craftghana.local").first():
        artisan = User(full_name="Demo Artisan", email="artisan@craftghana.local", role="artisan")
        artisan.set_password("artisan123")
        db.session.add(artisan)
        db.session.flush()
        if not Item.query.first():
            demo_items = [
                Item(title="Kente Cloth", description="Traditional handwoven fabric.", price=150.0, category="Textiles", artisan_id=artisan.id),
                Item(title="Wooden Stool", description="Hand-carved Ashanti stool.", price=300.0, category="Furniture", artisan_id=artisan.id),
                Item(title="Beaded Necklace", description="Handmade colorful beads.", price=75.0, category="Jewelry", artisan_id=artisan.id),
            ]
            for it in demo_items:
                db.session.add(it)
    db.session.commit()

# Optionally create_admin helper (not called automatically). We rely on /create-admin route.
def create_admin_helper(full_name, email, password):
    if User.query.filter_by(role="admin").first():
        raise RuntimeError("An admin already exists.")
    u = User(full_name=full_name, email=email, role="admin")
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    return u

# ---------- Confirm delivery route ----------
@app.route("/order/<int:order_id>/confirm_delivery", methods=["POST"])
@login_required
def confirm_delivery(order_id):
    """
    Buyer confirms delivery. Only allowed when order.status == 'shipped'.
    Notifies artisans (best-effort).
    """
    order = Order.query.get_or_404(order_id)
    if order.buyer_id != current_user.id:
        flash("You can only confirm delivery for your own orders.", "danger")
        return redirect(url_for("my_orders"))

    if order.status != "shipped":
        flash("Order is not marked as shipped yet.", "warning")
        return redirect(url_for("my_orders"))

    order.status = "delivered"
    db.session.commit()

    # notify artisans (optional, best-effort)
    if app.config.get("MAIL_USERNAME") and app.config.get("MAIL_PASSWORD"):
        try:
            artisan_emails = {oi.item.artisan.email for oi in order.order_items if oi.item and oi.item.artisan and oi.item.artisan.email}
            for email in artisan_emails:
                msg = Message(f"Order #{order.id} delivered", sender=app.config.get("MAIL_USERNAME"), recipients=[email])
                msg.body = f"Hello,\n\nOrder #{order.id} that contained your item(s) has been confirmed delivered by the buyer.\n\nThanks,\nCraftGhana"
                mail.send(msg)
        except Exception:
            app.logger.exception("Failed to send artisan delivery notifications")

    flash("Thank you for confirming delivery!", "success")
    return redirect(url_for("my_orders"))

# ---------- Run ----------
if __name__ == "__main__":
    with app.app_context():
        # create tables if they don't exist
        db.create_all()
        # NOTE: do NOT auto-seed admin in production. If you want demo data locally, uncomment next line (dev only):
        # seed_demo_data()
    app.run(debug=True)
