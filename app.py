import os, json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

from config import Config
from models import db, User, Match, MatchPlayer, Submission, SubmissionApproval, Leaderboard
from utils import make_token, read_token

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

mail = Mail(app)

with app.app_context():
    db.create_all()
    # bootstrap admin if not present
    admin_email = "eric.ranger@gmail.com"
    if admin_email and not User.query.filter_by(email=admin_email).first():
        admin = User(
            name="Admin",
            email=admin_email,
            commander="N/A",
            password_hash=generate_password_hash("admin123"),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    # compatible SQLAlchemy 2.x
    return db.session.get(User, int(user_id))

def load_objectives():
    with app.open_resource("objectives.json", "r") as f:
        return json.load(f)

OBJECTIVES = {o["id"]: o for o in load_objectives()}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        commander = request.form.get("commander","").strip()
        password = request.form.get("password","")
        if not (name and email and commander and password):
            flash("Tous les champs sont requis.", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Courriel déjà utilisé.", "warning")
            return redirect(url_for("register"))
        u = User(
            name=name,
            email=email,
            commander=commander,
            password_hash=generate_password_hash(password)
        )
        db.session.add(u)
        db.session.commit()
        flash("Inscription réussie. Vous pouvez vous connecter.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        u = User.query.filter_by(email=email).first()
        if u and check_password_hash(u.password_hash, password):
            login_user(u)
            return redirect(url_for("dashboard"))
        flash("Identifiants invalides.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    players = User.query.order_by(User.created_at.asc()).all()
    lb = db.session.query(Leaderboard, User).join(User, Leaderboard.user_id==User.id).order_by(Leaderboard.points.desc()).all()
    mp = MatchPlayer.query.filter_by(user_id=current_user.id).all()
    match_ids = [r.match_id for r in mp]
    matches = Match.query.filter(Match.id.in_(match_ids)).order_by(Match.round_number.asc()).all() if match_ids else []
    return render_template("dashboard.html", players=players, leaderboard=lb, matches=matches)

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if not current_pw or not new_pw or not confirm_pw:
            flash("Tous les champs sont requis.", "warning")
            return redirect(url_for("account"))

        if not check_password_hash(current_user.password_hash, current_pw):
            flash("Mot de passe actuel incorrect.", "danger")
            return redirect(url_for("account"))

        if new_pw != confirm_pw:
            flash("La confirmation ne correspond pas.", "warning")
            return redirect(url_for("account"))

        if len(new_pw) < 6:
            flash("Le nouveau mot de passe doit contenir au moins 6 caractères.", "warning")
            return redirect(url_for("account"))

        current_user.password_hash = generate_password_hash(new_pw)
        db.session.commit()
        flash("Mot de passe mis à jour avec succès ✅", "success")
        return redirect(url_for("dashboard"))

    return render_template("account.html")

@app.route("/admin/round/new", methods=["POST"])
@login_required
def admin_new_round():
    if not current_user.is_admin:
        abort(403)
    round_number = int(request.form.get("round_number", "1"))
    Match.query.filter_by(round_number=round_number).delete()
    db.session.commit()
    players = User.query.order_by(User.id.asc()).all()
    groups = [players[i:i+4] for i in range(0, len(players), 4)]
    created = []
    for g in groups:
        if len(g) < 2:
            continue
        m = Match(round_number=round_number)
        db.session.add(m)
        db.session.flush()
        for u in g:
            db.session.add(MatchPlayer(match_id=m.id, user_id=u.id))
        created.append(m.id)
    db.session.commit()
    flash(f"Créé {len(created)} tables pour la ronde {round_number}.", "success")
    return redirect(url_for("dashboard"))

@app.route("/match/<int:match_id>")
@login_required
def match_detail(match_id):
    m = Match.query.get_or_404(match_id)
    players = db.session.query(User).join(MatchPlayer, MatchPlayer.user_id==User.id).filter(MatchPlayer.match_id==m.id).all()
    submissions = Submission.query.filter_by(match_id=m.id).all()
    return render_template("match_detail.html", m=m, players=players, submissions=submissions, objectives=OBJECTIVES)

@app.route("/match/<int:match_id>/submit", methods=["GET","POST"])
@login_required
def match_submit(match_id):
    m = Match.query.get_or_404(match_id)
    if not MatchPlayer.query.filter_by(match_id=match_id, user_id=current_user.id).first():
        flash("Vous ne faites pas partie de cette table.", "warning")
        return redirect(url_for("dashboard"))
    players = db.session.query(User).join(MatchPlayer, MatchPlayer.user_id==User.id).filter(MatchPlayer.match_id==m.id).all()

    if request.method == "POST":
        payload = {}
        total = 0
        for oid, meta in OBJECTIVES.items():
            if meta["type"] == "bool":
                val = 1 if request.form.get(oid) == "on" else 0
            else:
                try:
                    val = int(request.form.get(oid, "0"))
                except:
                    val = 0
            payload[oid] = val
            if meta["type"] == "bool":
                total += meta["points"] * val
            else:
                total += meta["points"] * max(0, val)

        sub = Submission(match_id=match_id, user_id=current_user.id, payload=payload, total_points=total, status="pending")
        db.session.add(sub)
        db.session.commit()

        others = [p for p in players if p.id != current_user.id]
        for p in others:
            try:
                token = make_token({"submission_id": sub.id, "approver_id": p.id})
                approve_url = url_for("confirm_submission", token=token, decision="approve", _external=True)
                reject_url = url_for("confirm_submission", token=token, decision="reject", _external=True)
                msg = Message(
                    subject=f"[EDH Tournoi] Confirmation points - Ronde {m.round_number} (Table {m.id})",
                    recipients=[p.email]
                )
                msg.html = render_template("emails/confirm.html", submitter=current_user, m=m, payload=payload, total=total, approve_url=approve_url, reject_url=reject_url)
                mail.send(msg)
            except Exception as e:
                print("Mail error:", e)

        flash("Feuille soumise. Des courriels de confirmation ont été envoyés aux autres joueurs de la table.", "success")
        return redirect(url_for("match_detail", match_id=match_id))

    return render_template("match_submit.html", m=m, objectives=OBJECTIVES)

@app.route("/confirm/<token>/<decision>")
def confirm_submission(token, decision):
    try:
        data = read_token(token)
        submission_id = int(data["submission_id"])
        approver_id = int(data["approver_id"])
    except Exception:
        flash("Lien invalide ou expiré.", "danger")
        return redirect(url_for("index"))

    sub = Submission.query.get_or_404(submission_id)

    if not MatchPlayer.query.filter_by(match_id=sub.match_id, user_id=approver_id).first() or sub.user_id == approver_id:
        flash("Lien non autorisé.", "danger")
        return redirect(url_for("index"))

    exists = SubmissionApproval.query.filter_by(submission_id=sub.id, approver_id=approver_id).first()
    if not exists:
        a = SubmissionApproval(submission_id=sub.id, approver_id=approver_id, decision="approve" if decision=="approve" else "reject")
        db.session.add(a)
        db.session.commit()

    approvals = SubmissionApproval.query.filter_by(submission_id=sub.id).all()
    has_reject = any(a.decision=="reject" for a in approvals)
    has_approve = any(a.decision=="approve" for a in approvals)

    sub.status = "rejected" if has_reject else ("approved" if has_approve else "pending")
    db.session.commit()

    if sub.status == "approved":
        lb = Leaderboard.query.filter_by(user_id=sub.user_id).first()
        if not lb:
            lb = Leaderboard(user_id=sub.user_id, points=0)
            db.session.add(lb)
        lb.points += sub.total_points
        db.session.commit()

    flash(f"Soumission {sub.status}. Merci!", "success" if sub.status=="approved" else "warning")
    return redirect(url_for("index"))

@app.route("/leaderboard")
def leaderboard():
    entries = db.session.query(Leaderboard, User).join(User, Leaderboard.user_id==User.id).order_by(Leaderboard.points.desc()).all()
    return render_template("leaderboard.html", leaderboard=entries)

@app.route("/players")
def players():
    entries = User.query.order_by(User.created_at.asc()).all()
    return render_template("players.html", players=entries)

# ---------- Admin ----------
def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

@app.route("/admin")
@login_required
@admin_required
def admin_home():
    return render_template("admin.html")

@app.route("/admin/submissions")
@login_required
@admin_required
def admin_submissions():
    player_id = request.args.get("player_id", type=int)
    q = (
        db.session.query(Submission, User, Match)
        .join(User, Submission.user_id == User.id)
        .join(Match, Submission.match_id == Match.id)
    )
    if player_id:
        q = q.filter(Submission.user_id == player_id)
    submissions = q.order_by(Submission.created_at.desc()).all()
    players = User.query.order_by(User.name.asc()).all()
    return render_template("admin_submissions.html", submissions=submissions, players=players, selected=player_id, objectives=OBJECTIVES)

# ---------- Run ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
