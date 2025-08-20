from app import app, db, User
from werkzeug.security import generate_password_hash

players = [
    ("Alice",   "alice@test.com",   "Atraxa, Praetors' Voice"),
    ("Bob",     "bob@test.com",     "Edgar Markov"),
    ("Charlie", "charlie@test.com", "Niv-Mizzet, Parun"),
    ("Diana",   "diana@test.com",   "Krenko, Mob Boss"),
    ("Ethan",   "ethan@test.com",   "Muldrotha, the Gravetide"),
    ("Fiona",   "fiona@test.com",   "Kaalia of the Vast"),
    ("George",  "george@test.com",  "Chulane, Teller of Tales"),
    ("Hannah",  "hannah@test.com",  "Narset, Enlightened Exile"),
    ("Ian",     "ian@test.com",     "Korvold, Fae-Cursed King"),
    ("Julia",   "julia@test.com",   "Animar, Soul of Elements"),
    ("Kevin",   "kevin@test.com",   "Yuriko, the Tiger's Shadow"),
    ("Laura",   "laura@test.com",   "Golos, Tireless Pilgrim"),
    ("Mark",    "mark@test.com",    "Brago, King Eternal"),
    ("Nina",    "nina@test.com",    "Omnath, Locus of Creation"),
    ("Oscar",   "oscar@test.com",   "Marchesa, the Black Rose"),
    ("Paula",   "paula@test.com",   "Ezuri, Claw of Progress"),
    ("Quentin", "quentin@test.com", "The Ur-Dragon"),
    ("Rachel",  "rachel@test.com",  "Sythis, Harvest's Hand"),
    ("Steve",   "steve@test.com",   "Atraxa, Grand Unifier"),
    ("Tina",    "tina@test.com",    "Breya, Etherium Shaper"),
]

with app.app_context():
    for name, email, commander in players:
        if not User.query.filter_by(email=email).first():
            u = User(
                name=name,
                email=email,
                commander=commander,
                password_hash=generate_password_hash("test123"),
                is_admin=False
            )
            db.session.add(u)
    db.session.commit()
    print("✅ 20 joueurs ajoutés avec succès (mdp = test123)")
