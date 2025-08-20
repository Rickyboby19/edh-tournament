import os, json
from datetime import datetime
from itertools import combinations

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from jinja2 import TemplateNotFound
from sqlalchemy import func

from config import Config
from models import db, User, Match, MatchPlayer, Submission, SubmissionApproval, Leaderboard
from utils import make_token, read_token

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

mail = Mail(app)

# --------------------------- Bootstrap DB/Admin ---------------------------
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

# --------------------------- Objectives ---------------------------
import re
from json import JSONDecodeError

# Un petit barème par défaut si objectives.json est manquant/cassé
DEFAULT_OBJECTIVES = [
    {"id": "win_table", "label": "Victoire de table", "type": "bool", "points": 4},
    {"id": "kill_player", "label": "Eliminer un joueur", "type": "int",  "points": 1},
    {"id": "first_blood", "label": "First Blood", "type": "bool", "points": 1},
]

def _clean_json_like(text: str) -> str:
    """Tolère les commentaires et virgules finales: enlève //... et /* ... */, puis virgules pendantes."""
    # supprime commentaires // et /* */
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # supprime les virgules avant } ou ]
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text

def _list_to_dict(objs):
    out = {}
    for o in objs:
        oid = o.get("id")
        if not oid:
            continue
        # normalise
        typ = o.get("type", "bool")
        if typ not in ("bool", "int"):
            typ = "bool"
        pts = o.get("points", 0)
        try:
            pts = int(pts)
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
    """
    Charge objectives.json en étant tolérant (commentaires, virgules finales).
    Retourne toujours un dict {id: meta}.
    """
    path = os.path.join(app.root_path, "objectives.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        try:
            # tentative stricte
            objs = json.loads(raw)
        except JSONDecodeError:
            # tentative tolérante
            cleaned = _clean_json_like(raw)
            objs = json.loads(cleaned)
        if isinstance(objs, dict):
            # si l’utilisateur a mis un objet {id: {...}}
            return _list_to_dict([{"id": k, **(v or {})} for k, v in objs.items()])
        elif isinstance(objs, list):
            return _list_to_dict(objs)
        else:
            raise ValueError("Format d’objectives.json invalide (doit être liste ou objet)")
    except Exception as e:
        # fallback: ne pas bloquer le démarrage
        print(f"[WARN] objectives.json illisible: {e}. Utilisation du barème par défaut.")
        return _list_to_dict(DEFAULT_OBJECTIVES)

# IMPORTANT: maintenant load_objectives() RENVOIE déjà un dict
OBJECTIVES = load_objectives()


# --------------------------- Jinja helper: has_endpoint ---------------------------
@app.context_processor
def utility_processor():
    from flask import url_for as _url_for
    def has_endpoint(name: str) -> bool:
        try:
            _url_for(name)
            return True
        except Exception:
            return False
    return dict(has_endpoint=has_endpoint)

# --------------------------- Admin guard ---------------------------
def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

# --------------------------- Public ---------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.get("/reglements")
def reglements():
    try:
        # on passe OBJECTIVES au template pour afficher le barème dynamiquement
        return render_template("reglements.html", objectives=OBJECTIVES)
    except TemplateNotFound:
        # Fallback si le fichier manque toujours
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
            "Voici un aperçu du barème directement issu de <code>objectives.json</code> :</p>"
            + table_html,
            200,
        )

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

# --------------------------- Matches utilitaires ---------------------------
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

# --------------------------- Admin: home ---------------------------
@app.route("/admin")
@login_required
@admin_required
def admin_home():
    # Stats
    total_users = User.query.count()
    total_matches = Match.query.count()
    total_submissions = Submission.query.count()
    rounds = [
        r[0] for r in db.session.query(Match.round_number)
        .distinct().order_by(Match.round_number.asc()).all()
    ]

    # Sélecteurs + aperçu leaderboard
    players = User.query.order_by(User.name.asc()).all()
    leaderboard = (
        db.session.query(Leaderboard, User)
        .join(User, Leaderboard.user_id == User.id)
        .order_by(Leaderboard.points.desc())
        .all()
    )

    return render_template(
        "admin.html",
        total_users=total_users,
        total_matches=total_matches,
        total_submissions=total_submissions,
        rounds=rounds,
        players=players,
        leaderboard=leaderboard,
    )

# --------------------------- Admin: submissions list ---------------------------
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

# --------------------------- Admin: points update ---------------------------
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
    else:
        db.session.flush()

    if mode == "set":
        row.points = max(0, value)
    else:  # delta
        row.points = max(0, (row.points or 0) + value)

    db.session.commit()
    flash(f"Points de {u.name} mis à jour ({row.points}).", "success")
    return redirect(url_for("admin_home"))

# --------------------------- Admin: reset ---------------------------
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
            # ordre important : approvals -> submissions -> matchplayers -> matches
            n1 = SubmissionApproval.query.delete(synchronize_session=False)
            n2 = Submission.query.delete(synchronize_session=False)
            n3 = MatchPlayer.query.delete(synchronize_session=False)
            n4 = Match.query.delete(synchronize_session=False)
            deleted.append(f"approvals:{n1}, submissions:{n2}, matchplayers:{n3}, matches:{n4}")

        if scope == "all" and not keep_players:
            # éviter de supprimer l'admin pour ne pas te lock-out (optionnel)
            admin = User.query.filter_by(is_admin=True).first()
            if admin:
                User.query.filter(User.id != admin.id).delete(synchronize_session=False)
            else:
                User.query.delete(synchronize_session=False)
            deleted.append("users:reset")

        db.session.commit()
        flash("Réinitialisation effectuée (" + " | ".join(deleted) + ")", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur pendant la réinitialisation : {e}", "danger")

    return redirect(url_for("admin_home"))

# --------------------------- Admin: email ---------------------------
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
        # un seul email avec BCC (évite reply-all)
        msg = Message(subject=subject, recipients=[], bcc=recipients)
        msg.body = body
        msg.html = body.replace("\n", "<br>")
        mail.send(msg)
        flash(f"Courriel envoyé à {len(recipients)} destinataire(s).", "success")
    except Exception as e:
        flash(f"Erreur d’envoi : {e}", "danger")

    return redirect(url_for("admin_home"))

# --------------------------- Tournoi: heuristique d'appariement ---------------------------
def _build_rounds_max_unique(players_ids, max_rounds=5, table_size=4):
    """
    Construit jusqu'à max_rounds rondes de pods (taille 4) en minimisant
    les re-rencontres (pair repeats). Heuristique gloutonne suffisante pour 8–24 joueurs.
    Retour: List[List[List[int]]]  -> rounds -> tables -> user_ids
    """
    n = len(players_ids)
    if n < 2:
        return []

    # compteur de co-présences (paires)
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

        # Si le nombre ne tombe pas pile, on peut laisser une table à 3 (évite 2)
        while len(remaining) >= 3 and (len(remaining) >= table_size or len(remaining) in (3,)):
            # seed = joueur qui a le plus de collisions potentielles -> on place d'abord
            seed = max(remaining, key=lambda u: sum(pc(u, v) for v in remaining if v != u))
            remaining.remove(seed)

            # on choisit la meilleure combinaison de (table_size-1) autour du seed
            others = list(remaining)
            best = None
            best_score = None
            want = table_size - 1 if len(remaining) >= (table_size - 1) else len(remaining)
            for combo in combinations(others, want):
                cand = [seed] + list(combo)
                # score = somme des pair_count dans la table (on minimise)
                score = sum(pc(a,b) for a,b in combinations(cand, 2))
                if best is None or score < best_score:
                    best = cand
                    best_score = score

            # place la table
            for u in best[1:]:
                remaining.remove(u)
            tables.append(best)
            inc_pc(best)

        # s'il reste 1–2 joueurs isolés, on les “greffe” à des tables existantes (les plus petites)
        leftovers = list(remaining)
        if leftovers:
            # trie les tables par taille croissante puis par score d'impact
            tables.sort(key=lambda t: (len(t), sum(pc(a,b) for a,b in combinations(t,2))))
            for u in leftovers:
                # on ne dépasse pas 5 par table; priorité aux tables de 3
                placed = False
                for idx, t in enumerate(tables):
                    if len(t) < table_size:  # préfère <=4
                        # score d'ajout
                        _ = sum(pc(u, v) for v in t)  # métrique locale
                        tables[idx] = t + [u]
                        inc_pc([*t, u])
                        placed = True
                        break
                if not placed:
                    # en dernier recours, crée une mini-table (3) si rien d'autre ne convient
                    tables.append([u])

        # filtre: on valide seulement les tables à 3 ou 4
        tables = [t for t in tables if len(t) >= 3]
        if not tables:
            break
        rounds.append(tables)

    return rounds

# --------------------------- Tournoi: démarrage (rondes 1..5) ---------------------------
@app.post("/admin/tournament/start")
@login_required
@admin_required
def admin_tournament_start():
    # max 5 rondes par défaut
    max_rounds = request.form.get("max_rounds", type=int) or 5
    max_rounds = max(1, min(5, max_rounds))

    # joueurs pris au moment du lancement
    players = User.query.order_by(User.created_at.asc()).all()
    player_ids = [p.id for p in players]
    if len(player_ids) < 4:
        flash("Il faut au moins 4 joueurs pour démarrer le tournoi.", "warning")
        return redirect(url_for("admin_home"))

    # supprime anciennes données de saison (rondes 1..7) + leaderboard
    try:
        # on efface proprement dans l'ordre inverse des dépendances
        SubmissionApproval.query.delete(synchronize_session=False)
        Submission.query.delete(synchronize_session=False)
        MatchPlayer.query.delete(synchronize_session=False)
        Match.query.filter(Match.round_number.between(1, 7)).delete(synchronize_session=False)
        Leaderboard.query.delete(synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()

    # construit l’horaire
    schedule = _build_rounds_max_unique(player_ids, max_rounds=max_rounds, table_size=4)

    # enregistre les matches
    created = 0
    for r_idx, tables in enumerate(schedule, start=1):
        for table in tables:
            m = Match(round_number=r_idx)
            db.session.add(m)
            db.session.flush()
            for uid in table:
                db.session.add(MatchPlayer(match_id=m.id, user_id=uid))
            created += 1
    db.session.commit()

    max_unique = len(schedule) * 3  # par joueur, 3 adversaires par ronde
    msg = f"Tournoi démarré : {len(players)} joueurs, {len(schedule)} ronde(s), {created} table(s) créées. " \
          f"Chaque joueur peut rencontrer au plus {max_unique} adversaires uniques en {len(schedule)} rondes."
    flash(msg, "success")
    return redirect(url_for("admin_home"))

# --------------------------- Tournoi: demi-finales (round 6) ---------------------------
@app.post("/admin/tournament/semis")
@login_required
@admin_required
def admin_tournament_semis():
    # récupère top 8
    top = (
        db.session.query(Leaderboard, User)
        .join(User, Leaderboard.user_id == User.id)
        .order_by(Leaderboard.points.desc(), User.name.asc())
        .limit(8).all()
    )
    if len(top) < 8:
        flash("Moins de 8 joueurs au classement — impossible de générer les demi-finales.", "warning")
        return redirect(url_for("admin_home"))

    ids = [row.user_id for row, _ in top]  # ordonnés
    # serpentin: table A: 1,4,5,8 ; table B: 2,3,6,7
    a = [ids[0], ids[3], ids[4], ids[7]]
    b = [ids[1], ids[2], ids[5], ids[6]]

    # supprime anciennes phases 6/7 si elles existent
    try:
        m_ids = [m.id for m in Match.query.filter(Match.round_number.in_([6, 7])).all()]
        if m_ids:
            sub_ids = [sid for (sid,) in db.session.query(Submission.id).filter(Submission.match_id.in_(m_ids)).all()]
            if sub_ids:
                SubmissionApproval.query.filter(SubmissionApproval.submission_id.in_(sub_ids)).delete(synchronize_session=False)
                Submission.query.filter(Submission.id.in_(sub_ids)).delete(synchronize_session=False)
            MatchPlayer.query.filter(MatchPlayer.match_id.in_(m_ids)).delete(synchronize_session=False)
            Match.query.filter(Match.id.in_(m_ids)).delete(synchronize_session=False)
            db.session.commit()
    except Exception:
        db.session.rollback()

    # crée les 2 demi-finales (round 6)
    for table in (a, b):
        m = Match(round_number=6)
        db.session.add(m)
        db.session.flush()
        for uid in table:
            db.session.add(MatchPlayer(match_id=m.id, user_id=uid))
    db.session.commit()

    flash("Demi-finales créées (round 6) : 2 tables de 4 joueurs (seed serpentin).", "success")
    return redirect(url_for("admin_home"))

# --------------------------- Tournoi: finale (round 7) ---------------------------
@app.post("/admin/tournament/final")
@login_required
@admin_required
def admin_tournament_final():
    semis = Match.query.filter_by(round_number=6).all()
    if len(semis) != 2:
        flash("Il faut exactement 2 demi-finales (round 6) pour générer la finale.", "warning")
        return redirect(url_for("admin_home"))

    finalists = []
    for semi in semis:
        # joueurs de la demi
        players = [mp.user_id for mp in MatchPlayer.query.filter_by(match_id=semi.id).all()]
        if not players:
            continue

        # points approuvés dans cette demi uniquement
        rows = (
            db.session.query(Submission.user_id, func.coalesce(func.sum(Submission.total_points), 0))
            .filter(Submission.match_id == semi.id, Submission.status == "approved")
            .group_by(Submission.user_id)
            .all()
        )
        points_by_user = {uid: 0 for uid in players}
        for uid, pts in rows:
            points_by_user[uid] = pts or 0

        # top2
        top2 = sorted(points_by_user.items(), key=lambda kv: (-kv[1], kv[0]))[:2]
        finalists.extend([uid for uid, _ in top2])

    if len(finalists) != 4:
        flash("Impossible de déterminer 4 finalistes (vérifie les soumissions approuvées en demi).", "danger")
        return redirect(url_for("admin_home"))

    # supprime ancienne finale si existante
    try:
        old = Match.query.filter_by(round_number=7).all()
        old_ids = [m.id for m in old]
        if old_ids:
            sub_ids = [sid for (sid,) in db.session.query(Submission.id).filter(Submission.match_id.in_(old_ids)).all()]
            if sub_ids:
                SubmissionApproval.query.filter(SubmissionApproval.submission_id.in_(sub_ids)).delete(synchronize_session=False)
                Submission.query.filter(Submission.id.in_(sub_ids)).delete(synchronize_session=False)
            MatchPlayer.query.filter(MatchPlayer.match_id.in_(old_ids)).delete(synchronize_session=False)
            Match.query.filter(Match.id.in_(old_ids)).delete(synchronize_session=False)
            db.session.commit()
    except Exception:
        db.session.rollback()

    # crée la finale (round 7)
    m = Match(round_number=7)
    db.session.add(m)
    db.session.flush()
    for uid in finalists:
        db.session.add(MatchPlayer(match_id=m.id, user_id=uid))
    db.session.commit()

    flash("Finale (round 7) créée avec les 4 meilleurs des demi-finales.", "success")
    return redirect(url_for("admin_home"))

# --------------------------- Run ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
