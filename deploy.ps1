# deploy.ps1
# Déploiement "one-command" pour l'app Flask (Windows / PowerShell)
# - Active (ou crée) le venv
# - Met à jour pip et installe requirements
# - Crée config.py si absent
# - Initialise la base (import app)
# - Fait une micro-migration SQLite pour la colonne decklist_url
# - Démarre le serveur via waitress

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Se placer dans le dossier du script (racine du projet)
Set-Location -Path $PSScriptRoot

Write-Host "== Déploiement Flask (Windows) =="

# --- Vérifs de base -----------------------------------------------------------
if (-not (Test-Path ".\app.py")) {
  Write-Error "app.py introuvable dans $PWD. Lance le script depuis la racine du projet."
  exit 1
}

# Lien Discord (affichage seulement; la valeur par défaut existe dans config.py)
if ([string]::IsNullOrWhiteSpace($env:DISCORD_INVITE)) {
  Write-Host "DISCORD_INVITE non défini -> utilisation par défaut: https://discord.gg/K2VQ4EzZFZ"
} else {
  Write-Host "DISCORD_INVITE: $($env:DISCORD_INVITE)"
}

# --- Environnement virtuel ----------------------------------------------------
if (-not (Test-Path ".\.venv\Scripts\Activate.ps1")) {
  Write-Host "Création de l'environnement virtuel (.venv)…"
  python -m venv .venv
}
Write-Host "Activation du venv"
. .\.venv\Scripts\Activate.ps1

# --- pip & requirements -------------------------------------------------------
Write-Host "Mise à jour de pip"
python -m pip install --upgrade pip

if (-not (Test-Path ".\requirements.txt")) {
  Write-Host "requirements.txt absent -> génération minimale"
@"
Flask
Flask-SQLAlchemy
Flask-Login
SQLAlchemy
requests
waitress
"@ | Set-Content -Encoding UTF8 .\requirements.txt
} else {
  # Corrige un requirements.txt "cassé" contenant par erreur 'pip freeze > requirements.txt'
  $req = Get-Content .\requirements.txt -Raw
  if ($req -match 'pip freeze') {
    Write-Warning "requirements.txt contient une ligne invalide ('pip freeze'). Regénération minimale."
@"
Flask
Flask-SQLAlchemy
Flask-Login
SQLAlchemy
requests
waitress
"@ | Set-Content -Encoding UTF8 .\requirements.txt
  }
}

Write-Host "Installation depuis requirements.txt"
python -m pip install -r .\requirements.txt

# --- config.py auto-créé si manquant -----------------------------------------
if (-not (Test-Path ".\config.py")) {
  Write-Host "config.py manquant -> création d'un fichier de config par défaut"
@"
# config.py (auto-généré)
import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DISCORD_INVITE = os.getenv("DISCORD_INVITE", "https://discord.gg/K2VQ4EzZFZ")
"@ | Set-Content -Encoding UTF8 .\config.py
}

# --- Initialisation DB (import app.py -> db.create_all() s'il est dans app.py)-
Write-Host "Initialisation de la base (chargement app.py)…"
# On crée un petit script temporaire qui importe app.py
$tmpInit = Join-Path $env:TEMP ("initdb_" + [System.IO.Path]::GetRandomFileName() + ".py")
@"
import importlib.util, sys, os
sys.path.insert(0, os.getcwd())
mod = importlib.import_module('app')
print("Import app OK.")
"@ | Set-Content -Encoding UTF8 $tmpInit
try {
  python $tmpInit
} finally {
  Remove-Item $tmpInit -ErrorAction SilentlyContinue
}

# --- Migration légère SQLite pour la colonne decklist_url ---------------------
Write-Host "Migration SQLite (colonne decklist_url)…"
$tmpMig = Join-Path $env:TEMP ("migrate_" + [System.IO.Path]::GetRandomFileName() + ".py")
@"
import os, sqlite3, sys

uri = os.getenv("DATABASE_URL", "sqlite:///app.db")
if not uri.startswith("sqlite:///"):
    print("↷ Base non-SQLite ({}), migration ignorée.".format(uri))
    sys.exit(0)

db_path = uri.replace("sqlite:///", "", 1)
if not os.path.exists(db_path):
    print("ℹ︎ Fichier DB absent ({}), rien à migrer.".format(db_path))
    sys.exit(0)

conn = sqlite3.connect(db_path)
try:
    c = conn.cursor()
    # table présente ?
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tournament_players'")
    row = c.fetchone()
    if not row:
        print("ℹ︎ table 'tournament_players' absente (nouvelle base) — rien à migrer.")
        sys.exit(0)

    # colonne déjà là ?
    c.execute("PRAGMA table_info(tournament_players)")
    cols = [r[1] for r in c.fetchall()]
    if "decklist_url" in cols:
        print("✓ colonne 'decklist_url' déjà présente.")
        sys.exit(0)

    # ajout de colonne
    c.execute("ALTER TABLE tournament_players ADD COLUMN decklist_url VARCHAR(500)")
    conn.commit()
    print("✓ colonne 'decklist_url' ajoutée.")
finally:
    conn.close()
"@ | Set-Content -Encoding UTF8 $tmpMig
try {
  python $tmpMig
} finally {
  Remove-Item $tmpMig -ErrorAction SilentlyContinue
}

# --- Lancement serveur via waitress ------------------------------------------
$HostBind = if ($env:HOST -and $env:HOST.Trim() -ne "") { $env:HOST } else { "127.0.0.1" }
$Port = if ($env:PORT -and ($env:PORT -as [int])) { [int]$env:PORT } else { 5000 }

Write-Host "Démarrage sur http://$HostBind`:$Port (waitress)…"
# Utiliser le module pour éviter les soucis de PATH
python -m waitress --listen="$HostBind`:$Port" app:app
