"""Vérifie la chaîne /report Android → insert → événement temps réel (soutenance)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

fd, path = tempfile.mkstemp(suffix=".db")
os.close(fd)
os.environ["MOMOGUARD_DB"] = "sqlite:///" + path
os.environ.setdefault("MOMOGUARD_SECRET", "soutenance-check-secret-key-32chars")

from server import database, firebase_auth, app as appmod

database.set_database_url(os.environ["MOMOGUARD_DB"])
database.init_db()
appmod.ensure_default_admin()
appmod.app.config["WTF_CSRF_ENABLED"] = False
appmod.limiter.enabled = False

# Mock Firebase comme l'app Android (id_token présent)
firebase_auth._initialized = True
firebase_auth.verify_id_token = lambda t: {"uid": "demo-uid", "email": "demo@test.cd", "name": "Demo"}

client = appmod.app.test_client()

# 1) Liaison compte (comme AuthApi.link)
r = client.post("/api/auth/firebase", json={"id_token": "fake"})
assert r.status_code == 200, r.get_json()
print("OK auth firebase :", r.get_json().get("status"))

# 2) Sans approbation -> 403
r = client.post("/report", json={
    "platform": "android",
    "event_type": "sms",
    "content": "URGENT Orange Money http://0range-money.tk",
    "id_token": "fake",
    "uid": "demo-uid",
    "metadata": {"sender": "OrangeMoney"},
})
assert r.status_code == 403, r.get_json()
print("OK refus pending :", r.get_json().get("error"))

# 3) Approbation admin
database.set_user_status("demo-uid", "approved")

# 4) Rapport accepte + score
r = client.post("/report", json={
    "platform": "android",
    "event_type": "sms",
    "content": "URGENT: votre compte Orange Money sera suspendu. Reactivez sur http://0range-money.tk",
    "id_token": "fake",
    "uid": "demo-uid",
    "metadata": {"sender": "OrangeMoney"},
})
assert r.status_code == 201, r.get_json()
body = r.get_json()
print("OK report accepte : niveau=", body["level"], "score=", body["score"], "id=", body["id"])
assert body["level"] == "eleve"
assert body.get("reasons")

# 5) Visible dans /api/reports (dashboard)
client.post("/login", data={"username": "admin", "password": "momoguard"})
data = client.get("/api/reports").get_json()
assert any(x["id"] == body["id"] for x in data["reports"])
print("OK visible dans /api/reports (dashboard)")

# 6) Bouton demo soutenance
r = client.post("/demo")
assert r.status_code == 200 and r.get_json().get("ok")
print("OK /demo (bouton Simuler une alerte)")

# 7) CORS SocketIO en developpement
assert appmod._socketio_cors == "*" or "*" in str(appmod._socketio_cors)
print("OK CORS SocketIO developpement =", appmod._socketio_cors)

print("\n=== CHAINE AGENT -> SERVEUR -> DASHBOARD : OK ===")
try:
    os.remove(path)
except OSError:
    pass
