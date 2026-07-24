from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.secret_key = "secureiot123"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# -------------------------
# Database Tables
# -------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(100))
    device_type = db.Column(db.String(100))
    ip_address = db.Column(db.String(100))
    status = db.Column(db.String(50))


class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(200))
    level = db.Column(db.String(50))


# -------------------------
# Home
# -------------------------

@app.route("/")
def home():
    return render_template("index.html")


# -------------------------
# Register
# -------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        fullname = request.form["fullname"]
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user:
            flash("Email already exists")
            return redirect("/register")

        new_user = User(
            fullname=fullname,
            email=email,
            password=password
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration Successful")
        return redirect("/login")

    return render_template("register.html")


# -------------------------
# Login
# -------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(
            email=email,
            password=password
        ).first()

        if user:
            session["user"] = user.fullname
            return redirect("/dashboard")

        flash("Invalid Email or Password")

    return render_template("login.html")


# -------------------------
# Dashboard
# -------------------------

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    device_count = Device.query.count()
    log_count = SecurityLog.query.count()

    return render_template(
        "dashboard.html",
        name=session["user"],
        device_count=device_count,
        log_count=log_count
    )
    # -------------------------
# View Devices
# -------------------------

@app.route("/devices")
def devices():

    if "user" not in session:
        return redirect("/login")

    all_devices = Device.query.all()

    return render_template(
        "devices.html",
        devices=all_devices
    )


# -------------------------
# Add Device
# -------------------------

@app.route("/add_device", methods=["GET", "POST"])
def add_device():

    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":

        device = Device(
            device_name=request.form["device_name"],
            device_type=request.form["device_type"],
            ip_address=request.form["ip_address"],
            status=request.form["status"]
        )

        db.session.add(device)

        log = SecurityLog(
            event=f"Device Added: {device.device_name}",
            level="INFO"
        )

        db.session.add(log)

        db.session.commit()

        return redirect("/devices")

    return render_template("add_device.html")


# -------------------------
# Delete Device
# -------------------------

@app.route("/delete_device/<int:id>")
def delete_device(id):

    if "user" not in session:
        return redirect("/login")

    device = Device.query.get(id)

    if device:

        log = SecurityLog(
            event=f"Device Deleted: {device.device_name}",
            level="WARNING"
        )

        db.session.add(log)
        db.session.delete(device)
        db.session.commit()

    return redirect("/devices")


# -------------------------
# Security Logs
# -------------------------

@app.route("/security_logs")
def security_logs():

    if "user" not in session:
        return redirect("/login")

    logs = SecurityLog.query.order_by(SecurityLog.id.desc()).all()

    return render_template(
        "security_logs.html",
        logs=logs
    )


# -------------------------
# Threat Detection
# -------------------------

@app.route("/threat_detection")
def threat_detection():

    if "user" not in session:
        return redirect("/login")

    threats = []

    devices = Device.query.all()

    for d in devices:

        if d.status == "Offline":

            threats.append(
                f"{d.device_name} is Offline - Possible Threat"
            )

    return render_template(
        "threat_detection.html",
        threats=threats
    )


# -------------------------
# Logout
# -------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# -------------------------
# Run Application
# -------------------------

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)
    