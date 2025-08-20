import os, json, re
from datetime import datetime
from itertools import combinations

import requests
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from jinja2 import TemplateNotFound
from sqlalchemy import func, text

from config import Config
from models import db, User, Match, MatchPlayer, Submission, SubmissionApproval, Leaderboard

# --------------------------------------------------------------------------------------
# App & Login
# --------------------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --------------------------------------------------------------------------------------
# Modèles multi-tournois (propres à app.py)
# --------------------------------------------------------------------------------------
class Tournament(db.Model):
    __tablename__ = "tournaments"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, default="Tournoi EDH")
    status = db.Column(db.String(20), nullable=False, default="pending")  # pending|started|finished|cancelled
    rounds_planned = db.Column(db.Integer, nullable=False, default=5)
    current_round = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)

class TournamentPlayer(db.Model):
    __tablename__ = "tournament_players"
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournaments.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    commander = db.Column(db.String(120))
    decklist_url = db.Column(db.String(500))  # visible admins seulement dans les templates
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)

class TournamentMatch(db.Model):
    __tablename__ = "tournament_matches"
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey("tournaments.id"), nullable=False, index=True)
    match_id = db.Column(db.Integer, db.ForeignKey(f"{Match.__tablename__}.id"), nullable=False, index=True)
    __table_args__ = (db.UniqueConstraint("tournament_id", "match_id", name="uq_tournament_match"),)

# --------------------------------------------------------------------------------------
# Bootstrap DB, admin par défaut, tournoi par défaut + correctif colonne decklist_url
# --------------------------------------------------------------------------------------
with app.app_context():
    db.create_all()

    # Ajoute decklist_url si la colonne manque encore (SQLite)
    try:
        info = db.session.execute(text("PRAGMA table_info(tournament_players)")).fetchall()
        cols = {row[1] for row in info}  # row[1] = name
        if "decklist_url" not in cols:
            db.session.execute(text("ALTER TABLE tournament_players ADD COLUMN decklist_url VARCHAR(500)"))
            db.session.commit()
            print("[DB] Colonne tournament_players.decklist_url ajoutée automatiquement.")
    except Exception as e:
        print("[WARN] Impossible de vérifier/ajouter decklist_url :", e)

    # Admin par défaut
    admin_email = "eric.ranger@gmail.com"
    if admin_email and not User.query.filter_by(email=admin_email).first():
        admin = User(
            name="Admin",
            email=admin_email,
            commander="",  # non utilisé ici
            password_hash=generate_password_hash("admin123"),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

    # Tournoi par défaut si aucun en attente/en cours
    if not Tournament.query.filter(Tournament.status.in_(["pending", "started"])).first():
        db.session.add(Tournament(name="Tournoi EDH", status="pending", rounds_planned=5, current_round=1))
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --------------------------------------------------------------------------------------
# Objectives (tolérant au JSON “salissant”)
# --------------------------------------------------------------------------------------
DEFAULT_OBJECTIVES = [
    {"id": "win_table", "label": "Victoire de table", "type": "bool", "points": 4},
    {"id": "kill_player", "label": "Éliminer un joueur", "type": "int",  "points": 1},
    {"id": "first_blood", "label": "First Blood", "type": "bool", "points": 1},
]

def _clean_json_like(text: str) -> str:
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text

def _list_to_dict(objs):
    out = {}
    for o in objs:
        oid = o.get("id")
        if not oid:
            continue
        typ = o.get("type", "bool")
        if typ not in ("bool", "int"):
            typ = "bool"
        try:
            pts = int(o.get("points", 0))
        except Exception:
            pts = 0
        out[oid] = {
            "id": oid,
            "label": o.get("label", oid.replace("_", " ").title()),
            "type": typ,
            "points": pts,
        }
    return out

def load_objectives() -> dict:
    path = os.path.join(app.root_path, "objectives.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        try:
            objs = json.loads(raw)
        except json.JSONDecodeError:
            cleaned = _clean_json_like(raw)
            objs = json.loads(cleaned)
        if isinstance(objs, dict):
            return _list_to_dict([{"id": k, **(v or {})} for k, v in objs.items()])
        elif isinstance(objs, list):
            return _list_to_dict(objs)
        else:
            raise ValueError("Format d’objectives.json invalide (doit être liste ou objet)")
    except Exception as e:
        print(f"[WARN] objectives.json illisible: {e}. Utilisation du barème par défaut.")
        return _list_to_dict(DEFAULT_OBJECTIVES)

OBJECTIVES = load_objectives()

# --------------------------------------------------------------------------------------
# Helpers globaux (injectés dans les templates)
# --------------------------------------------------------------------------------------
@app.context_processor
def utility_processor():
    from flask import url_for as _url_for

    def has_endpoint(name: str) -> bool:
        try:
            _url_for(name)
            return True
        except Exception:
            return False

    def tournament_status():
        t = Tournament.query.filter(Tournament.status.in_(["pending", "started"]))\
                            .order_by(Tournament.created_at.desc()).first()
        return t.status if t else "pending"

    def is_registered_for(tournament_id: int, user_id: int) -> bool:
        return db.session.query(TournamentPlayer.id)\
            .filter_by(tournament_id=tournament_id, user_id=user_id).first() is not None

    # Lien d’invitation Discord (ENV ou valeur par défaut)
    discord_invite = os.getenv("DISCORD_INVITE_URL", "https://discord.gg/K2VQ4EzZFZ")

    return dict(
        has_endpoint=has_endpoint,
        tournament_status=tournament_status,
        is_registered_for=is_registered_for,
        discord_invite=discord_invite,
    )

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def send_discord(message: str):
    """Envoi facultatif sur Discord via webhook."""
    url = os.getenv("DISCORD_WEBHOOK_URL")
    if not url:
        return
    try:
        payload = {"content": message[:2000]}
        username = os.getenv("DISCORD_WEBHOOK_USERNAME") or "Spelltable QC Bot"
        payload["username"] = username
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print("[Discord webhook] erreur:", e)

# --------------------------------------------------------------------------------------
# Public
# --------------------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.get("/reglements")
def reglements():
    try:
        return render_template("reglements.html", objectives=OBJECTIVES)
    except TemplateNotFound:
        rows = []
        for oid, meta in OBJECTIVES.items():
            label = meta.get("label", oid.replace("_", " ").title())
            typ = meta.get("type", "bool")
            pts = meta.get("points", 0)
            if typ == "bool":
                rows.append(f"<tr><td>{label}</td><td>Oui/Non</td><td>{pts} pts</td></tr>")
            else:
                rows.append(f"<tr><td>{label}</td><td>Quantité</td><td>{pts} pts / unité</td></tr>")
        table_html = (
            "<table border='1' cellpadding='6'><thead><tr>"
            "<th>Objectif</th><th>Type</th><th>Barème</th></tr></thead>"
            "<tbody>" + "".join(rows) + "</tbody></table>"
        )
        return (
            "<!doctype html><meta charset='utf-8'>"
            "<h1>Règlements du tournoi</h1>"
            "<p>Le fichier <code>templates/reglements.html</code> est manquant. "
            "Voici un aperçu du barème depuis <code>objectives.json</code> :</p>"
            + table_html,
            200,
        )

# --------------------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not (name and email and password):
            flash("Tous les champs sont requis.", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Courriel déjà utilisé.", "warning")
            return redirect(url_for("register"))
        u = User(
            name=name,
            email=email,
            commander="",  # désormais par tournoi
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

# --------------------------------------------------------------------------------------
# Tournaments (liste + détail)
# --------------------------------------------------------------------------------------
@app.get("/tournaments")
@login_required
def tournaments_list():
    tournaments = Tournament.query.order_by(
        db.case(
            (Tournament.status == "started", 0),
            (Tournament.status == "pending", 1),
            else_=2
        ),
        Tournament.created_at.desc()
    ).all()
    try:
        return render_template("tournaments.html", tournaments=tournaments)
    except TemplateNotFound:
        items = "".join(
            f"<li><a href='{url_for('tournament_detail', tournament_id=t.id)}'>{t.name}</a> "
            f"(statut: {t.status}, rondes: {t.current_round}/{t.rounds_planned})</li>"
            for t in tournaments
        )
        return f"<!doctype html><meta charset='utf-8'><h1>Tournois</h1><ul>{items or '<li>Aucun tournoi</li>'}</ul>"

@app.get("/tournaments/<int:tournament_id>")
@login_required
def tournament_detail(tournament_id: int):
    t = Tournament.query.get_or_404(tournament_id)

    registered = (
        db.session.query(TournamentPlayer, User)
        .join(User, TournamentPlayer.user_id == User.id)
        .filter(TournamentPlayer.tournament_id == t.id)
        .order_by(User.name.asc())
        .all()
    )

    current_tables = []
    if t.status in ("pending", "started"):
        matches = (
            db.session.query(Match)
            .join(TournamentMatch, TournamentMatch.match_id == Match.id)
            .filter(TournamentMatch.tournament_id == t.id, Match.round_number == t.current_round)
            .order_by(Match.id.asc())
            .all()
        )
        for m in matches:
            players = (
                db.session.query(User)
                .join(MatchPlayer, MatchPlayer.user_id == User.id)
                .filter(MatchPlayer.match_id == m.id)
                .order_by(User.name.asc())
                .all()
            )
            current_tables.append({"match": m, "players": players})

    try:
        return render_template(
            "tournament_detail.html",
            t=t, registered=registered, current_tables=current_tables, objectives=OBJECTIVES
        )
    except TemplateNotFound:
        reg_html = "".join(
            f"<li>{u.name} — <em>{tp.commander or 'Commander non renseigné'}</em></li>"
            for tp, u in registered
        ) or "<li>Aucun joueur inscrit</li>"
        tables_html = ""
        if current_tables:
            tables_html += "<ul>"
            for row in current_tables:
                plist = ", ".join(p.name for p in row["players"])
                tables_html += f"<li>Table {row['match'].id}: {plist}</li>"
            tables_html += "</ul>"
        else:
            tables_html = "<p>Aucune table pour la ronde courante.</p>"
        return (
            f"<!doctype html><meta charset='utf-8'>"
            f"<h1>{t.name}</h1>"
            f"<p>Statut: {t.status} — Ronde: {t.current_round}/{t.rounds_planned}</p>"
            f"<h2>Inscrits</h2><ul>{reg_html}</ul>"
            f"<h2>Tables (ronde {t.current_round})</h2>{tables_html}"
        )

# --------------------------------------------------------------------------------------
# API Commanders (autocomplete + image) — utilise Scryfall (fiable)
# --------------------------------------------------------------------------------------
@app.get("/api/commanders")
@login_required
def api_commanders_search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify([])
    try:
        url = "https://api.scryfall.com/cards/search"
        params = {"q": f'type:legendary type:creature {q}'}
        r = requests.get(url, params=params, timeout=8)
        r.raise_for_status()
        data = r.json()
        out = []
        for card in data.get("data", [])[:15]:
            name = card.get("name")
            img = (card.get("image_uris") or {}).get("normal") or \
                  (card.get("image_uris") or {}).get("large")
            formats = card.get("legalities", {})
            legal = formats.get("commander") in ("legal", "restricted")
            out.append({"name": name, "image": img, "commander_legal": legal})
        return jsonify(out)
    except Exception as e:
        print("[Scryfall] erreur:", e)
        return jsonify([])

@app.get("/api/commander_image")
@login_required
def api_commander_image():
    name = (request.args.get("name") or "").strip()
    if not name:
        return jsonify({"image": None})
    try:
        url = "https://api.scryfall.com/cards/named"
        r = requests.get(url, params={"exact": name}, timeout=8)
        r.raise_for_status()
        card = r.json()
        img = (card.get("image_uris") or {}).get("normal") or \
              (card.get("image_uris") or {}).get("large")
        return jsonify({"image": img})
    except Exception as e:
        print("[Scryfall] erreur:", e)
        return jsonify({"image": None})

# --------------------------------------------------------------------------------------
# Inscriptions par tournoi (côté joueur)
# --------------------------------------------------------------------------------------
@app.post("/tournaments/<int:tournament_id>/register")
@login_required
def tournament_register(tournament_id: int):
    t = Tournament.query.get_or_404(tournament_id)
    if t.status != "pending":
        flash("Les inscriptions sont fermées (tournoi démarré).", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))

    commander = (request.form.get("commander") or "").strip()
    decklist_url = (request.form.get("decklist_url") or "").strip()
    if not commander:
        flash("Merci d’indiquer votre commandant pour ce tournoi.", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))

    exists = TournamentPlayer.query.filter_by(tournament_id=t.id, user_id=current_user.id).first()
    if exists:
        exists.commander = commander
        exists.decklist_url = decklist_url or exists.decklist_url
        db.session.commit()
        flash("Commandant (et decklist si fourni) mis à jour ✅", "success")
    else:
        db.session.add(TournamentPlayer(
            tournament_id=t.id, user_id=current_user.id,
            commander=commander, decklist_url=decklist_url or None
        ))
        db.session.commit()
        flash("Inscription au tournoi confirmée ✅", "success")
    return redirect(url_for("tournament_detail", tournament_id=t.id))

@app.post("/tournaments/<int:tournament_id>/unregister")
@login_required
def tournament_unregister(tournament_id: int):
    t = Tournament.query.get_or_404(tournament_id)
    if t.status != "pending":
        flash("Impossible de se désinscrire après le démarrage.", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))
    TournamentPlayer.query.filter_by(tournament_id=t.id, user_id=current_user.id).delete()
    db.session.commit()
    flash("Désinscription effectuée.", "success")
    return redirect(url_for("tournament_detail", tournament_id=t.id))

# --------------------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    lb = (
        db.session.query(Leaderboard, User)
        .join(User, Leaderboard.user_id==User.id)
        .order_by(Leaderboard.points.desc())
        .all()
    )
    mp = MatchPlayer.query.filter_by(user_id=current_user.id).all()
    match_ids = [r.match_id for r in mp]
    matches = (
        Match.query.filter(Match.id.in_(match_ids))
        .order_by(Match.round_number.asc()).all()
        if match_ids else []
    )

    pending_q = (
        db.session.query(Submission)
        .join(Match, Submission.match_id == Match.id)
        .join(MatchPlayer, MatchPlayer.match_id == Match.id)
        .filter(
            Submission.status == "pending",
            MatchPlayer.user_id == current_user.id,
            Submission.user_id != current_user.id
        )
    )
    pending_count = pending_q.count()

    tournaments = Tournament.query.order_by(Tournament.created_at.desc()).all()
    my_regs = {
        t.id: db.session.query(TournamentPlayer).filter_by(tournament_id=t.id, user_id=current_user.id).first()
        for t in tournaments
    }

    return render_template("dashboard.html",
                           leaderboard=lb, matches=matches,
                           tournaments=tournaments, my_regs=my_regs,
                           pending_count=pending_count)

# --------------------------------------------------------------------------------------
# Matches & soumissions
# --------------------------------------------------------------------------------------
@app.route("/match/<int:match_id>")
@login_required
def match_detail(match_id):
    m = Match.query.get_or_404(match_id)
    players = (
        db.session.query(User)
        .join(MatchPlayer, MatchPlayer.user_id==User.id)
        .filter(MatchPlayer.match_id==m.id).all()
    )
    submissions = Submission.query.filter_by(match_id=m.id).all()
    return render_template("match_detail.html", m=m, players=players, submissions=submissions, objectives=OBJECTIVES)

@app.route("/match/<int:match_id>/submit", methods=["GET","POST"])
@login_required
def match_submit(match_id):
    m = Match.query.get_or_404(match_id)
    if not MatchPlayer.query.filter_by(match_id=match_id, user_id=current_user.id).first():
        flash("Vous ne faites pas partie de cette table.", "warning")
        return redirect(url_for("dashboard"))
    players = (
        db.session.query(User)
        .join(MatchPlayer, MatchPlayer.user_id==User.id)
        .filter(MatchPlayer.match_id==m.id).all()
    )

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

        sub = Submission(
            match_id=match_id,
            user_id=current_user.id,
            payload=payload,
            total_points=total,
            status="pending"
        )
        db.session.add(sub)
        db.session.commit()

        others = [p for p in players if p.id != current_user.id]
        names = ", ".join(p.name for p in others)
        send_discord(f"[Tournoi] Feuille soumise par {current_user.name} pour la ronde {m.round_number} (table {m.id}). "
                     f"Joueurs à confirmer: {names}. Ouvrez /submissions/pending pour valider.")

        flash("Feuille soumise ✅ Les autres joueurs doivent valider dans « Confirmations ».", "success")
        return redirect(url_for("match_detail", match_id=match_id))

    return render_template("match_submit.html", m=m, objectives=OBJECTIVES)

# Confirmations internes
@app.get("/submissions/pending")
@login_required
def submissions_pending():
    q = (
        db.session.query(Submission, Match)
        .join(Match, Submission.match_id == Match.id)
        .join(MatchPlayer, MatchPlayer.match_id == Match.id)
        .filter(
            Submission.status == "pending",
            MatchPlayer.user_id == current_user.id,
            Submission.user_id != current_user.id
        )
        .order_by(Submission.created_at.desc())
    )
    items = q.all()
    try:
        return render_template("submissions_pending.html", items=items, objectives=OBJECTIVES)
    except TemplateNotFound:
        rows = []
        for sub, m in items:
            rows.append(
                f"<li>Ronde {m.round_number} (table {m.id}) — "
                f"<a href='{url_for('submission_decide', submission_id=sub.id, decision='approve')}'>Approuver</a> | "
                f"<a href='{url_for('submission_decide', submission_id=sub.id, decision='reject')}'>Rejeter</a></li>"
            )
        return "<h1>Confirmations en attente</h1><ul>" + "".join(rows or ["<li>Aucune</li>"]) + "</ul>"

@app.get("/submissions/<int:submission_id>/<decision>")
@login_required
def submission_decide(submission_id: int, decision: str):
    sub = Submission.query.get_or_404(submission_id)
    at_table = db.session.query(MatchPlayer).filter_by(match_id=sub.match_id, user_id=current_user.id).first()
    if not at_table or sub.user_id == current_user.id:
        flash("Action non autorisée.", "danger")
        return redirect(url_for("submissions_pending"))

    exists = SubmissionApproval.query.filter_by(submission_id=sub.id, approver_id=current_user.id).first()
    if not exists:
        a = SubmissionApproval(
            submission_id=sub.id,
            approver_id=current_user.id,
            decision="approve" if decision=="approve" else "reject"
        )
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

    flash(f"Soumission {sub.status}.", "success" if sub.status=="approved" else ("warning" if sub.status=="pending" else "danger"))
    return redirect(url_for("submissions_pending"))

# --------------------------------------------------------------------------------------
# Classements & joueurs
# --------------------------------------------------------------------------------------
@app.route("/leaderboard")
def leaderboard():
    entries = (
        db.session.query(Leaderboard, User)
        .join(User, Leaderboard.user_id==User.id)
        .order_by(Leaderboard.points.desc()).all()
    )
    return render_template("leaderboard.html", leaderboard=entries)

@app.route("/players")
def players():
    entries = User.query.order_by(User.created_at.asc()).all()
    return render_template("players.html", players=entries)

# --------------------------------------------------------------------------------------
# Admin - Accueil / Users / Submissions
# --------------------------------------------------------------------------------------
@app.route("/admin")
@login_required
@admin_required
def admin_home():
    total_users = User.query.count()
    total_matches = Match.query.count()
    total_submissions = Submission.query.count()
    rounds_present = [
        r[0] for r in db.session.query(Match.round_number)
        .distinct().order_by(Match.round_number.asc()).all()
    ]
    players = User.query.order_by(User.name.asc()).all()
    leaderboard = (
        db.session.query(Leaderboard, User)
        .join(User, Leaderboard.user_id == User.id)
        .order_by(Leaderboard.points.desc())
        .all()
    )
    tournaments = Tournament.query.order_by(
        db.case(
            (Tournament.status == "started", 0),
            (Tournament.status == "pending", 1),
            else_=2
        ),
        Tournament.created_at.desc()
    ).all()
    return render_template(
        "admin.html",
        total_users=total_users,
        total_matches=total_matches,
        total_submissions=total_submissions,
        rounds=rounds_present,
        players=players,
        leaderboard=leaderboard,
        tournaments=tournaments,
    )

@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.name.asc()).all()
    return render_template("admin_users.html", users=users)

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
    return render_template(
        "admin_submissions.html",
        submissions=submissions,
        players=players,
        selected=player_id,
        objectives=OBJECTIVES
    )

# --------------------------------------------------------------------------------------
# Admin - Points & Reset
# --------------------------------------------------------------------------------------
@app.post("/admin/points/update")
@login_required
@admin_required
def admin_points_update():
    user_id = request.form.get("user_id", type=int)
    mode = request.form.get("mode", "delta")
    value = request.form.get("value", type=int)

    if not user_id or value is None:
        flash("Paramètres incomplets.", "warning")
        return redirect(url_for("admin_home"))

    u = db.session.get(User, user_id)
    if not u:
        flash("Joueur introuvable.", "danger")
        return redirect(url_for("admin_home"))

    row = Leaderboard.query.filter_by(user_id=user_id).first()
    if not row:
        row = Leaderboard(user_id=user_id, points=0)
        db.session.add(row)

    if mode == "set":
        row.points = max(0, value)
    else:
        row.points = max(0, (row.points or 0) + value)

    db.session.commit()
    flash(f"Points de {u.name} mis à jour ({row.points}).", "success")
    return redirect(url_for("admin_home"))

@app.post("/admin/reset")
@login_required
@admin_required
def admin_reset():
    scope = request.form.get("scope", "scores")   # scores | matches | all
    keep_players = request.form.get("keep_players") == "on"
    deleted = []
    try:
        if scope in ("scores", "all"):
            n = Leaderboard.query.delete(synchronize_session=False)
            deleted.append(f"scores:{n}")
        if scope in ("matches", "all"):
            n1 = SubmissionApproval.query.delete(synchronize_session=False)
            n2 = Submission.query.delete(synchronize_session=False)
            n3 = MatchPlayer.query.delete(synchronize_session=False)
            n4 = Match.query.delete(synchronize_session=False)
            n5 = TournamentMatch.query.delete(synchronize_session=False)
            deleted.append(f"approvals:{n1}, submissions:{n2}, matchplayers:{n3}, matches:{n4}, tournament_matches:{n5}")
        if scope == "all" and not keep_players:
            admin = User.query.filter_by(is_admin=True).first()
            if admin:
                User.query.filter(User.id != admin.id).delete(synchronize_session=False)
            else:
                User.query.delete(synchronize_session=False)
            deleted.append("users:reset")
        TournamentPlayer.query.delete(synchronize_session=False)
        Tournament.query.delete(synchronize_session=False)
        db.session.add(Tournament(name="Tournoi EDH", status="pending", rounds_planned=5, current_round=1))
        db.session.commit()
        flash("Réinitialisation effectuée (" + " | ".join(deleted) + ")", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur pendant la réinitialisation : {e}", "danger")
    return redirect(url_for("admin_home"))

# --------------------------------------------------------------------------------------
# Admin - Tournois (créer/démarrer/avancer/reculer/annuler) & manipuler les inscriptions
# --------------------------------------------------------------------------------------
@app.post("/admin/tournaments/create")
@login_required
@admin_required
def admin_tournament_create():
    name = (request.form.get("name") or "Tournoi EDH").strip()
    rounds_planned = max(1, min(5, request.form.get("rounds_planned", type=int) or 5))
    t = Tournament(name=name, status="pending", rounds_planned=rounds_planned, current_round=1)
    db.session.add(t)
    db.session.commit()
    flash(f"Tournoi créé: {t.name} ({rounds_planned} rondes prévues).", "success")
    return redirect(url_for("tournament_detail", tournament_id=t.id))

def _build_rounds_max_unique(players_ids, max_rounds=5, table_size=4):
    n = len(players_ids)
    if n < 2:
        return []
    pair_count = {}
    def pc(a,b):
        return pair_count.get((a,b) if a<b else (b,a), 0)
    def inc_pc(table):
        for a,b in combinations(table, 2):
            k = (a,b) if a<b else (b,a)
            pair_count[k] = pair_count.get(k,0) + 1
    rounds = []
    ids = list(players_ids)
    for _ in range(max_rounds):
        remaining = set(ids)
        tables = []
        while len(remaining) >= 3 and (len(remaining) >= table_size or len(remaining) in (3,)):
            seed = max(remaining, key=lambda u: sum(pc(u, v) for v in remaining if v != u))
            remaining.remove(seed)
            others = list(remaining)
            best = None
            best_score = None
            want = table_size - 1 if len(remaining) >= (table_size - 1) else len(remaining)
            for combo in combinations(others, want):
                cand = [seed] + list(combo)
                score = sum(pc(a,b) for a,b in combinations(cand, 2))
                if best is None or score < best_score:
                    best = cand
                    best_score = score
            for u in best[1:]:
                remaining.remove(u)
            tables.append(best)
            inc_pc(best)
        leftovers = list(remaining)
        if leftovers:
            tables.sort(key=lambda t: (len(t), sum(pc(a,b) for a,b in combinations(t,2))))
            for u in leftovers:
                placed = False
                for idx, t_ in enumerate(tables):
                    if len(t_) < table_size:
                        tables[idx] = t_ + [u]
                        inc_pc([*t_, u])
                        placed = True
                        break
                if not placed:
                    tables.append([u])
        tables = [t_ for t_ in tables if len(t_) >= 3]
        if not tables:
            break
        rounds.append(tables)
    return rounds

@app.post("/admin/tournaments/<int:tournament_id>/start")
@login_required
@admin_required
def admin_tournament_start(tournament_id: int):
    t = Tournament.query.get_or_404(tournament_id)
    if t.status == "started":
        flash("Ce tournoi est déjà démarré.", "info")
        return redirect(url_for("tournament_detail", tournament_id=t.id))

    max_rounds = max(1, min(5, request.form.get("max_rounds", type=int) or t.rounds_planned or 5))
    t.rounds_planned = max_rounds

    regs = TournamentPlayer.query.filter_by(tournament_id=t.id).all()
    player_ids = [r.user_id for r in regs]
    if len(player_ids) < 4:
        flash("Il faut au moins 4 joueurs inscrits pour démarrer le tournoi.", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))

    # Nettoyage des matches existants de CE tournoi
    try:
        m_ids = [mid for (mid,) in db.session.query(TournamentMatch.match_id).filter_by(tournament_id=t.id).all()]
        if m_ids:
            sub_ids = [sid for (sid,) in db.session.query(Submission.id).filter(Submission.match_id.in_(m_ids)).all()]
            if sub_ids:
                SubmissionApproval.query.filter(SubmissionApproval.submission_id.in_(sub_ids)).delete(synchronize_session=False)
                Submission.query.filter(Submission.id.in_(sub_ids)).delete(synchronize_session=False)
            MatchPlayer.query.filter(MatchPlayer.match_id.in_(m_ids)).delete(synchronize_session=False)
            Match.query.filter(Match.id.in_(m_ids)).delete(synchronize_session=False)
            TournamentMatch.query.filter_by(tournament_id=t.id).delete(synchronize_session=False)
            db.session.commit()
    except Exception:
        db.session.rollback()

    schedule = _build_rounds_max_unique(player_ids, max_rounds=max_rounds, table_size=4)
    created = 0
    for r_idx, tables in enumerate(schedule, start=1):
        for table in tables:
            m = Match(round_number=r_idx)
            db.session.add(m)
            db.session.flush()
            db.session.add(TournamentMatch(tournament_id=t.id, match_id=m.id))
            for uid in table:
                db.session.add(MatchPlayer(match_id=m.id, user_id=uid))
            created += 1

    t.status = "started"
    t.current_round = 1
    t.started_at = datetime.utcnow()
    db.session.commit()

    send_discord(f"[Tournoi] « {t.name} » démarré avec {len(player_ids)} joueurs, {len(schedule)} ronde(s), {created} table(s).")
    flash(f"Tournoi démarré: {len(player_ids)} joueurs, {len(schedule)} ronde(s), {created} table(s).", "success")
    return redirect(url_for("tournament_detail", tournament_id=t.id))

@app.post("/admin/tournaments/<int:tournament_id>/round/next")
@login_required
@admin_required
def admin_tournament_round_next(tournament_id: int):
    t = Tournament.query.get_or_404(tournament_id)
    if t.status != "started":
        flash("Le tournoi doit être démarré.", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))
    if t.current_round < t.rounds_planned:
        t.current_round += 1
        db.session.commit()
        flash(f"Passage à la ronde {t.current_round}.", "success")
    else:
        flash("Dernière ronde atteinte.", "info")
    return redirect(url_for("tournament_detail", tournament_id=t.id))

@app.post("/admin/tournaments/<int:tournament_id>/round/prev")
@login_required
@admin_required
def admin_tournament_round_prev(tournament_id: int):
    t = Tournament.query.get_or_404(tournament_id)
    if t.status != "started":
        flash("Le tournoi doit être démarré.", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))
    if t.current_round > 1:
        t.current_round -= 1
        db.session.commit()
        flash(f"Retour à la ronde {t.current_round}.", "success")
    else:
        flash("Déjà à la première ronde.", "info")
    return redirect(url_for("tournament_detail", tournament_id=t.id))

@app.post("/admin/tournaments/<int:tournament_id>/cancel")
@login_required
@admin_required
def admin_tournament_cancel(tournament_id: int):
    t = Tournament.query.get_or_404(tournament_id)

    # Supprimer matches et données associées de CE tournoi
    try:
        m_ids = [mid for (mid,) in db.session.query(TournamentMatch.match_id).filter_by(tournament_id=t.id).all()]
        if m_ids:
            sub_ids = [sid for (sid,) in db.session.query(Submission.id).filter(Submission.match_id.in_(m_ids)).all()]
            if sub_ids:
                SubmissionApproval.query.filter(SubmissionApproval.submission_id.in_(sub_ids)).delete(synchronize_session=False)
                Submission.query.filter(Submission.id.in_(sub_ids)).delete(synchronize_session=False)
            MatchPlayer.query.filter(MatchPlayer.match_id.in_(m_ids)).delete(synchronize_session=False)
            Match.query.filter(Match.id.in_(m_ids)).delete(synchronize_session=False)
            TournamentMatch.query.filter_by(tournament_id=t.id).delete(synchronize_session=False)
        TournamentPlayer.query.filter_by(tournament_id=t.id).delete(synchronize_session=False)
        t.status = "cancelled"
        t.finished_at = datetime.utcnow()
        db.session.commit()
        flash("Tournoi annulé et données associées nettoyées.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur pendant l’annulation: {e}", "danger")

    return redirect(url_for("admin_home"))

# Admin: manipuler les inscriptions
@app.post("/admin/tournaments/<int:tournament_id>/register")
@login_required
@admin_required
def admin_tournament_register_user(tournament_id: int):
    t = Tournament.query.get_or_404(tournament_id)
    if t.status != "pending":
        flash("Inscriptions fermées (tournoi démarré).", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))
    user_id = request.form.get("user_id", type=int)
    commander = (request.form.get("commander") or "").strip()
    decklist_url = (request.form.get("decklist_url") or "").strip()
    if not user_id or not commander:
        flash("Utilisateur et commandant requis.", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))
    exists = TournamentPlayer.query.filter_by(tournament_id=t.id, user_id=user_id).first()
    if exists:
        exists.commander = commander
        exists.decklist_url = decklist_url or exists.decklist_url
    else:
        db.session.add(TournamentPlayer(
            tournament_id=t.id, user_id=user_id,
            commander=commander, decklist_url=decklist_url or None
        ))
    db.session.commit()
    flash("Inscription mise à jour par l’admin.", "success")
    return redirect(url_for("tournament_detail", tournament_id=t.id))

@app.post("/admin/tournaments/<int:tournament_id>/unregister")
@login_required
@admin_required
def admin_tournament_unregister_user(tournament_id: int):
    t = Tournament.query.get_or_404(tournament_id)
    if t.status != "pending":
        flash("Inscriptions fermées (tournoi démarré).", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))
    user_id = request.form.get("user_id", type=int)
    if not user_id:
        flash("Utilisateur requis.", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))
    TournamentPlayer.query.filter_by(tournament_id=t.id, user_id=user_id).delete()
    db.session.commit()
    flash("Désinscription effectuée par l’admin.", "success")
    return redirect(url_for("tournament_detail", tournament_id=t.id))

# --------------------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
