import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from database import get_db, init_db

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
app.secret_key = os.environ.get("SECRET_KEY", "hostel_complaint_system_secure_key_2026")
init_db()
# Master Management Security Passcode for the Single Admin
STAFF_SECURITY_KEY = os.environ.get("STAFF_SECURITY_KEY", "STAFF2026")

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "pdf"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ================= HOME =================
@app.route("/")
def home():
    return render_template("home.html")


# ================= STUDENT REGISTER NUMBER LOGIN & ACCESS =================
@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip().upper()
        password = request.form.get("password", "").strip()

        if not student_id:
            flash("Please enter your Student Register Number.", "danger")
            return render_template("student_login.html")

        conn = get_db()
        student = conn.execute("SELECT * FROM students WHERE student_id = ?", (student_id,)).fetchone()

        # Instant auto-registration on first entry by Register Number
        if not student:
            default_name = f"Student ({student_id})"
            hashed_pw = generate_password_hash(password if password else "12345")
            conn.execute("""
                INSERT INTO students (student_id, name, password)
                VALUES (?, ?, ?)
            """, (student_id, default_name, hashed_pw))
            conn.commit()
            student = conn.execute("SELECT * FROM students WHERE student_id = ?", (student_id,)).fetchone()

        # Verify password or auto-login with default password
        if check_password_hash(student["password"], password) or check_password_hash(student["password"], "12345") or not password:
            session.clear()
            session["student_id"] = student["student_id"]
            session["student_name"] = student["name"]
            flash(f"Welcome to Hostel Complaint Portal, {student['name']}!", "success")
            conn.close()
            return redirect(url_for("student_dashboard"))

        conn.close()
        flash("Invalid password for this Register Number.", "danger")

    return render_template("student_login.html")


# ================= STUDENT REGISTER ROUTE =================
@app.route("/student/register", methods=["GET", "POST"])
def student_register():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip().upper()
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")

        if not student_id or not name or not password:
            flash("All fields are required.", "danger")
            return render_template("student_register.html")

        conn = get_db()
        existing = conn.execute("SELECT 1 FROM students WHERE student_id = ?", (student_id,)).fetchone()
        if existing:
            conn.close()
            flash("Student Register Number already exists. Please log in directly.", "info")
            return redirect(url_for("student_login"))

        hashed_pw = generate_password_hash(password)
        conn.execute("INSERT INTO students (student_id, name, password) VALUES (?, ?, ?)",
                     (student_id, name, hashed_pw))
        conn.commit()
        conn.close()

        flash("Registration successful! Accessing your dashboard...", "success")
        session.clear()
        session["student_id"] = student_id
        session["student_name"] = name
        return redirect(url_for("student_dashboard"))

    return render_template("student_register.html")


# ================= STUDENT DASHBOARD =================
@app.route("/student/dashboard")
def student_dashboard():
    if "student_id" not in session:
        flash("Please enter your Student Register Number to access the portal.", "danger")
        return redirect(url_for("student_login"))

    selected_status = request.args.get("status", "All")
    conn = get_db()

    if selected_status != "All":
        complaints = conn.execute("""
            SELECT * FROM complaints 
            WHERE student_id = ? AND status = ?
            ORDER BY id DESC
        """, (session["student_id"], selected_status)).fetchall()
    else:
        complaints = conn.execute("""
            SELECT * FROM complaints 
            WHERE student_id = ?
            ORDER BY id DESC
        """, (session["student_id"],)).fetchall()

    conn.close()

    return render_template("student_dashboard.html", complaints=complaints, selected_status=selected_status)


# ================= RAISE COMPLAINT =================
@app.route("/student/complaint", methods=["GET", "POST"])
def raise_complaint():
    if "student_id" not in session:
        flash("Please enter your Student Register Number to submit a complaint.", "danger")
        return redirect(url_for("student_login"))

    if request.method == "POST":
        category = request.form.get("category", "").strip()
        location = request.form.get("location", "").strip()
        description = request.form.get("description", "").strip()

        if not category or not location or not description:
            flash("All fields are required.", "danger")
            return render_template("raise_complaint.html")

        conn = get_db()
        conn.execute("""
            INSERT INTO complaints (student_id, category, location, description, status)
            VALUES (?, ?, ?, ?, ?)
        """, (session["student_id"], category, location, description, "Pending"))
        conn.commit()
        conn.close()

        flash("Complaint submitted successfully! Management will review it shortly.", "success")
        return redirect(url_for("student_dashboard"))

    return render_template("raise_complaint.html")


# ================= SINGLE ADMIN LOGIN =================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        staff_key = request.form.get("staff_key", "").strip()

        # Enforce Master Passcode Verification
        if staff_key != STAFF_SECURITY_KEY:
            flash("Access Denied: Invalid Management Master Passcode.", "danger")
            return render_template("admin_login.html")

        # Enforce Single Admin Account
        if username != "admin":
            flash("Access Denied: Only the primary designated Management Administrator can log in.", "danger")
            return render_template("admin_login.html")

        conn = get_db()
        admin = conn.execute("SELECT * FROM admins WHERE username = 'admin'").fetchone()
        conn.close()

        if admin and check_password_hash(admin["password"], password):
            session.clear()
            session["admin"] = "admin"
            flash("Single Management Administrator authentication successful.", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid Management Password.", "danger")

    return render_template("admin_login.html")


# ================= ADMIN REGISTER (DISABLED FOR SINGLE ADMIN) =================
@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
    flash("Management registration is disabled. Only 1 single management account is permitted.", "warning")
    return redirect(url_for("admin_login"))


# ================= ADMIN DASHBOARD =================
@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin" not in session:
        flash("Please log in to access the management portal.", "danger")
        return redirect(url_for("admin_login"))

    selected_status = request.args.get("status", "All")
    conn = get_db()

    # Calculate statistics
    all_complaints = conn.execute("SELECT status FROM complaints").fetchall()
    stats = {
        "total": len(all_complaints),
        "pending": sum(1 for c in all_complaints if c["status"] == "Pending"),
        "in_progress": sum(1 for c in all_complaints if c["status"] == "In Progress"),
        "rectified": sum(1 for c in all_complaints if c["status"] == "Rectified"),
        "resolved": sum(1 for c in all_complaints if c["status"] == "Resolved")
    }

    if selected_status != "All":
        complaints = conn.execute("""
            SELECT * FROM complaints 
            WHERE status = ?
            ORDER BY id DESC
        """, (selected_status,)).fetchall()
    else:
        complaints = conn.execute("""
            SELECT * FROM complaints 
            ORDER BY id DESC
        """).fetchall()

    conn.close()

    return render_template("admin_dashboard.html", complaints=complaints, stats=stats, selected_status=selected_status)


# ================= UPDATE COMPLAINT =================
@app.route("/admin/update/<int:complaint_id>", methods=["POST"])
def update_complaint(complaint_id):
    if "admin" not in session:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("admin_login"))

    status = request.form.get("status", "Pending")
    rectification = request.form.get("rectification", "").strip()
    proof_filename = None

    file = request.files.get("proof")
    if file and file.filename and allowed_file(file.filename):
        ext = file.filename.rsplit(".", 1)[1].lower()
        proof_filename = secure_filename(f"{uuid.uuid4().hex}.{ext}")
        file.save(os.path.join(UPLOAD_FOLDER, proof_filename))

    conn = get_db()
    if proof_filename:
        conn.execute("""
            UPDATE complaints
            SET status = ?, rectification = ?, proof = ?
            WHERE id = ?
        """, (status, rectification, proof_filename, complaint_id))
    else:
        conn.execute("""
            UPDATE complaints
            SET status = ?, rectification = ?
            WHERE id = ?
        """, (status, rectification, complaint_id))

    conn.commit()
    conn.close()

    flash(f"Complaint #{complaint_id} updated successfully.", "success")
    return redirect(url_for("admin_dashboard"))


# ================= PROOF FILE SERVING =================
@app.route("/uploads/<filename>")
def uploads(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
