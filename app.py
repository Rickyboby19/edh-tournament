import os, json, re
from datetime import datetime
from itertools import combinations

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from jinja2 import TemplateNotFound
from json import JSONDecodeError

from config import Config
from models import db, User, Match, MatchPlayer, Submission, SubmissionApproval, Leaderboard
from utils import make_token, read_token

# -----------------------------------------------------------------------------
# App / Extensions
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

mail = Mail(app)

# -----------------------------------------------------------------------------
# Modèles spécifiques au multi-tournois (rajoutés ici pour ne pas toucher models.py)
# -----------------------------------------------------------------------------
class Tournament(db.Model):
    __tablename__ = "tournaments"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, default="Tournoi EDH")
    status = db.Column(db.String(20), nullable=False, default="pending")  # pending|started|finished
    rounds_planned = db.Column(db.Integer, nullable=False, default=5)
    current_round = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)

class TournamentPlayer(db.Model):
    __tablename__ = "tournament_players"
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey("tournaments.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey(f"{User.__tablename__}.id"), nullable=False, index=True)
    commander = db.Column(db.String(200), nullable=True)
    decklist_url = db.Column(db.String(500), nullable=True)  # <-- AJOUT
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("tournament_id", "user_id", name="uq_tournament_user"),)



class TournamentMatch(db.Model):
    """Mappe un Match existant à un Tournament, sans modifier la table Match."""
    __tablename__ = "tournament_matches"
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey("tournaments.id"), nullable=False, index=True)
    match_id = db.Column(db.Integer, db.ForeignKey(f"{Match.__tablename__}.id"), nullable=False, index=True)
    __table_args__ = (db.UniqueConstraint("tournament_id", "match_id", name="uq_tournament_match"),)

# -----------------------------------------------------------------------------
# Bootstrap DB / Admin
# -----------------------------------------------------------------------------
with app.app_context():
    db.create_all()
    # admin par défaut si absent
    admin_email = "eric.ranger@gmail.com"
    if admin_email and not User.query.filter_by(email=admin_email).first():
        admin = User(
            name="Admin",
            email=admin_email,
            commander="",  # le commandant n'est plus stocké au compte
            password_hash=generate_password_hash("admin123"),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
    # au moins un tournoi pending s'il n'y a rien d'actif
    if not Tournament.query.filter(Tournament.status.in_(["pending", "started"])).first():
        db.session.add(Tournament(name="Tournoi EDH", status="pending", rounds_planned=5, current_round=1))
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# -----------------------------------------------------------------------------
# Objectives loader tolérant (accepte JSON avec virgules traînantes / commentaires)
# -----------------------------------------------------------------------------
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
        except JSONDecodeError:
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

# -----------------------------------------------------------------------------
# Helpers (Jinja + décorateur admin)
# -----------------------------------------------------------------------------
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
        t = Tournament.query.filter(Tournament.status.in_(["pending", "started"])) \
                            .order_by(Tournament.created_at.desc()).first()
        return t.status if t else "pending"

    def is_registered_for(tournament_id: int, user_id: int) -> bool:
        return db.session.query(TournamentPlayer.id) \
            .filter_by(tournament_id=tournament_id, user_id=user_id).first() is not None

    return dict(
        has_endpoint=has_endpoint,
        tournament_status=tournament_status,
        is_registered_for=is_registered_for
    )

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

# -----------------------------------------------------------------------------
# Public
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------
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
            commander="",  # le commandant est maintenant saisi par tournoi
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

# -----------------------------------------------------------------------------
# Tournois
# -----------------------------------------------------------------------------
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

@app.post("/tournaments/<int:tournament_id>/register")
@login_required
def tournament_register(tournament_id: int):
    t = Tournament.query.get_or_404(tournament_id)
    if t.status != "pending":
        flash("Les inscriptions sont fermées (tournoi démarré).", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))

    commander = (request.form.get("commander") or "").strip()
    if not commander:
        flash("Merci d’indiquer votre commandant pour ce tournoi.", "warning")
        return redirect(url_for("tournament_detail", tournament_id=t.id))
    decklist_url = (request.form.get("decklist_url") or "").strip()

    exists = TournamentPlayer.query.filter_by(tournament_id=t.id, user_id=current_user.id).first()
    if exists:
        exists.commander = commander
        exists.decklist_url = decklist_url  # <-- AJOUT
        db.session.commit()
        flash("Commandant et decklist mis à jour pour ce tournoi ✅", "success")
    else:
        db.session.add(TournamentPlayer(
            tournament_id=t.id,
            user_id=current_user.id,
            commander=commander,
            decklist_url=decklist_url,  # <-- AJOUT
        ))
        db.session.commit()
        flash("Inscription au tournoi confirmée ✅", "success")

    return redirect(url_for("tournament_detail", tournament_id=t.id))

    tp = TournamentPlayer.query.filter_by(tournament_id=t.id, user_id=current_user.id).first()
    if tp:
        tp.commander = commander
        tp.decklist_url = decklist_url or None
    else:
        tp = TournamentPlayer(
            tournament_id=t.id,
            user_id=current_user.id,
            commander=commander,
            decklist_url=decklist_url or None,
        )
        db.session.add(tp)

    db.session.commit()
    flash("Inscription/commandant mis à jour ✅", "success")
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

# Anciennes routes (redirigées)
@app.post("/tournament/register")
@login_required
def old_tournament_register():
    flash("Inscription déplacée. Choisis un tournoi dans l’onglet Tournois.", "info")
    return redirect(url_for("tournaments_list"))

@app.post("/tournament/unregister")
@login_required
def old_tournament_unregister():
    flash("Désinscription déplacée. Choisis un tournoi dans l’onglet Tournois.", "info")
    return redirect(url_for("tournaments_list"))

# -----------------------------------------------------------------------------
# Dashboard
# -----------------------------------------------------------------------------
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
    tournaments = Tournament.query.order_by(Tournament.created_at.desc()).all()
    my_regs = {
        t.id: db.session.query(TournamentPlayer).filter_by(tournament_id=t.id, user_id=current_user.id).first()
        for t in tournaments
    }
    return render_template("dashboard.html",
                           leaderboard=lb, matches=matches,
                           tournaments=tournaments, my_regs=my_regs)

# -----------------------------------------------------------------------------
# Compte
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Matches / Soumissions
# -----------------------------------------------------------------------------
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
                except Exception:
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
        for p in others:
            try:
                token = make_token({"submission_id": sub.id, "approver_id": p.id})
                approve_url = url_for("confirm_submission", token=token, decision="approve", _external=True)
                reject_url = url_for("confirm_submission", token=token, decision="reject", _external=True)
                msg = Message(
                    subject=f"[EDH Tournoi] Confirmation points - Ronde {m.round_number} (Table {m.id})",
                    recipients=[p.email]
                )
                msg.html = render_template(
                    "emails/confirm.html",
                    submitter=current_user, m=m, payload=payload, total=total,
                    approve_url=approve_url, reject_url=reject_url
                )
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
        a = SubmissionApproval(
            submission_id=sub.id,
            approver_id=approver_id,
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

    flash(f"Soumission {sub.status}. Merci!", "success" if sub.status=="approved" else "warning")
    return redirect(url_for("index"))

# -----------------------------------------------------------------------------
# Classement & joueurs
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Admin: accueil (stats + tournois + raccourcis)
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Admin: créer / démarrer / contrôles du tournoi
# -----------------------------------------------------------------------------
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
    """Heuristique gloutonne pour limiter les re-rencontres, tables de 3–4."""
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
                for idx, ttable in enumerate(tables):
                    if len(ttable) < table_size:
                        tables[idx] = ttable + [u]
                        inc_pc([*ttable, u])
                        placed = True
                        break
                if not placed:
                    tables.append([u])
        tables = [t for t in tables if len(t) >= 3]
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

    # Nettoyage des matches déjà mappés sur ce tournoi
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
    
# ---------------------------------------------------------------------
# Compatibilité ancienne UI: /admin/round/new (remplacé par Tournois)
# ---------------------------------------------------------------------
@app.post("/admin/round/new")
@login_required
@admin_required
def admin_new_round():
    flash(
        "La génération de tables par ronde a été remplacée par le système Tournois. "
        "Va dans l’onglet « Tournois », inscris les joueurs, puis clique « Démarrer le tournoi ».",
        "info"
    )
    return redirect(url_for("tournaments_list"))


# -----------------------------------------------------------------------------
# Admin: liste des soumissions
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Admin: points
# -----------------------------------------------------------------------------
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

# ---------- Admin : gestion des joueurs (liste + suppression) ----------
@app.get("/admin/users")
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.name.asc()).all()
    admin_count = User.query.filter_by(is_admin=True).count()
    return render_template("admin_users.html", users=users, admin_count=admin_count)

@app.post("/admin/users/<int:user_id>/delete")
@login_required
@admin_required
def admin_user_delete(user_id: int):
    # on ne peut pas se supprimer soi-même
    if current_user.id == user_id:
        flash("Tu ne peux pas te supprimer toi-même.", "warning")
        return redirect(url_for("admin_users"))

    u = db.session.get(User, user_id)
    if not u:
        flash("Joueur introuvable.", "warning")
        return redirect(url_for("admin_users"))

    # garde-fous admin
    if u.is_admin:
        force = request.form.get("force_admin") == "on"
        admin_count = User.query.filter_by(is_admin=True).count()
        if not force:
            flash("Coche « forcer (si admin) » pour supprimer un admin.", "warning")
            return redirect(url_for("admin_users"))
        if admin_count <= 1:
            flash("Impossible de supprimer le dernier admin.", "danger")
            return redirect(url_for("admin_users"))

    # efface proprement ses données liées
    sub_ids = [sid for (sid,) in db.session.query(Submission.id).filter_by(user_id=user_id).all()]
    if sub_ids:
        SubmissionApproval.query.filter(SubmissionApproval.submission_id.in_(sub_ids)).delete(synchronize_session=False)
    SubmissionApproval.query.filter_by(approver_id=user_id).delete(synchronize_session=False)
    Submission.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    MatchPlayer.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    TournamentPlayer.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    Leaderboard.query.filter_by(user_id=user_id).delete(synchronize_session=False)

    db.session.delete(u)
    db.session.commit()
    flash("Joueur supprimé.", "success")
    return redirect(url_for("admin_users"))



# -----------------------------------------------------------------------------
# Admin: reset
# -----------------------------------------------------------------------------
@app.post("/admin/reset")
@login_required
@admin_required
def admin_reset():
    scope = request.form.get("scope", "scores")
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

# -----------------------------------------------------------------------------
# Admin: rôles (accorder/retirer admin)
# -----------------------------------------------------------------------------
@app.post("/admin/users/<int:user_id>/admin")
@login_required
@admin_required
def admin_user_admin(user_id: int):
    """Accorde ou retire le rôle admin à un joueur (sécurité: ne retire pas le dernier admin)."""
    action = request.form.get("action", "grant")
    u = db.session.get(User, user_id)
    if not u:
        flash("Joueur introuvable.", "danger")
        return redirect(url_for("admin_home"))

    if action == "grant":
        if u.is_admin:
            flash(f"{u.name} est déjà admin.", "info")
        else:
            u.is_admin = True
            db.session.commit()
            flash(f"{u.name} est maintenant admin ✅", "success")

    elif action == "revoke":
        if not u.is_admin:
            flash(f"{u.name} n'est pas admin.", "info")
        else:
            total_admins = User.query.filter_by(is_admin=True).count()
            if total_admins <= 1:
                flash("Impossible de retirer le dernier administrateur (sécurité).", "warning")
            else:
                u.is_admin = False
                db.session.commit()
                flash(f"Droits admin retirés à {u.name}.", "success")
    else:
        flash("Action invalide.", "warning")

    return redirect(url_for("admin_home"))

# -----------------------------------------------------------------------------
# Admin: email (optionnel)
# -----------------------------------------------------------------------------
@app.post("/admin/email")
@login_required
@admin_required
def admin_email():
    mode = request.form.get("recipients_mode", "selected")
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()

    if not subject or not body:
        flash("Sujet et message sont requis.", "warning")
        return redirect(url_for("admin_home"))

    recipients = []
    if mode == "all":
        recipients = [u.email for u in User.query.order_by(User.name.asc()).all() if u.email]
    else:
        ids = request.form.getlist("player_ids")
        if ids:
            users = User.query.filter(User.id.in_(ids)).all()
            recipients = [u.email for u in users if u.email]

    if not recipients:
        flash("Aucun destinataire trouvé.", "warning")
        return redirect(url_for("admin_home"))

    try:
        msg = Message(subject=subject, recipients=[], bcc=recipients)
        msg.body = body
        msg.html = body.replace("\n", "<br>")
        mail.send(msg)
        flash(f"Courriel envoyé à {len(recipients)} destinataire(s).", "success")
    except Exception as e:
        flash(f"Erreur d’envoi : {e}", "danger")

    return redirect(url_for("admin_home"))

# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
