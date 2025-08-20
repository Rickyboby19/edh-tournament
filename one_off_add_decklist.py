# one_off_add_decklist.py
"""
Ajoute la colonne decklist_url à tournament_players si elle n'existe pas.
Sûr à exécuter plusieurs fois (no-op si déjà présent).
"""

from app import app, db
from sqlalchemy import text

with app.app_context():
    # Vérifie la structure de la table
    cols = db.session.execute(text("PRAGMA table_info(tournament_players)")).fetchall()
    col_names = {c[1] for c in cols}  # c[1] = name

    if "decklist_url" in col_names:
        print("[OK] La colonne decklist_url existe déjà.")
    else:
        print("[...] Ajout de la colonne decklist_url...")
        db.session.execute(text("ALTER TABLE tournament_players ADD COLUMN decklist_url VARCHAR(500)"))
        db.session.commit()
        print("[OK] Colonne decklist_url ajoutée avec succès.")

