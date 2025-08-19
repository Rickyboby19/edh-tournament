# MTG EDH — Gestionnaire de Tournoi (Flask)

Une application Flask minimale pour gérer un tournoi de MTG Commander (EDH) : inscription/joueurs, tables par rondes, soumissions de points avec objectifs, validation par courriel et leaderboard.

## Fonctionnalités
- Inscription & connexion (nom, courriel, commandant, mot de passe)
- Liste des joueurs, leaderboard
- Admin : génération automatique des tables d'une ronde (groupes de 4)
- Soumission des points par joueur avec objectifs/penalités fournis
- Courriels de confirmation aux 3 autres joueurs de la table (liens approuver/refuser)
- Les points s'ajoutent au leaderboard dès la première approbation (et aucune contestation)

## Installation (Windows ou Linux/Mac)
1. Installez Python 3.10+ (3.11/3.12/3.13 OK).
2. Ouvrez un terminal dans ce dossier puis :
   ```bash
   python -m venv .venv
   .venv\Scripts\activate   # Windows
   # source .venv/bin/activate  # Linux/Mac
   pip install -r requirements.txt
   ```
3. Copiez `.env.example` vers `.env` et remplissez vos variables (SECRET_KEY, SMTP, ADMIN_EMAIL).
4. Lancez le serveur :
   ```bash
   set FLASK_APP=app.py  # Windows (PowerShell: $env:FLASK_APP='app.py')
   flask run --host=0.0.0.0 --port=5000
   ```
   Ou :
   ```bash
   python app.py
   ```

## SMTP
- Pour Gmail, activez l'authentification à deux facteurs et créez un **App Password**. Mettez-le dans `MAIL_PASSWORD`.
- Sinon utilisez le SMTP de votre FAI/serveur local (ex: postfix).

## Admin
- L'utilisateur avec le courriel `ADMIN_EMAIL` est créé automatisquement au démarrage (mot de passe `admin123` que vous devez changer).
- Dans le **Tableau de bord**, section Admin :
  - Entrez le numéro de ronde (1–5 pour la saison, 6=Top8, 7=Finale) puis cliquez **Générer des tables**.
  - Les joueurs sont répartis par groupe de 4 selon leur ordre d'inscription.

## Flux de match
1. L'admin génère les tables pour une ronde.
2. Chaque joueur ouvre sa table et clique **Soumettre mes points**, coche/compte les objectifs/penalités et envoie.
3. Les 3 autres reçoivent un courriel avec deux liens **Approuver / Refuser**.
4. Dès qu'une approbation est enregistrée (et aucune contestation), les points sont ajoutés au leaderboard.

## Personnalisation
- Les objectifs sont dans `objectives.json` (id, label, points, type). Vous pouvez les ajuster.
- Le style est dans `static/styles.css`.

## Sécurité & limites
- Projet minimal pour hébergement à la maison. Pour la prod : servez via nginx + gunicorn, utilisez HTTPS, activez CSRF, et ajoutez des vérifications métier supplémentaires.
- Les courriels contiennent des liens signés (itsdangerous). Vous pouvez ajuster la politique d'approbation (exigence: 2 approbations) dans `app.py`.

Bon tournoi !
