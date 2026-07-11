"""Génère la documentation PDF ligne par ligne du code MoMoGuard."""
import ast
import os
import re
from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(ROOT, "DOCUMENTATION_CODE_MOMOGUARD.pdf")

FICHIERS = [
    ("run.py", "Point d'entrée — lance le serveur central."),
    ("server/app.py", "Serveur Flask : routes, auth admin, API agents, WebSocket."),
    ("server/database.py", "Couche SQLAlchemy : tables, requêtes, conseils."),
    ("server/scoring.py", "Moteur de détection par règles explicables."),
    ("server/threat_intel.py", "Vérification URL via Google Safe Browsing."),
    ("server/firebase_auth.py", "Auth mobile Firebase + notifications push."),
    ("agents/windows_agent.py", "Agent Windows : presse-papier, navigateur, fichiers."),
    ("server/static/dashboard.js", "Dashboard temps réel (JavaScript)."),
    ("scripts/seed_demo.py", "Insertion de données de démonstration."),
    ("scripts/backup_db.py", "Sauvegarde JSON de la base."),
    ("evaluation/evaluer.py", "Évaluation chiffrée du moteur de scoring."),
]

FONT_PATHS = [r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\arial.ttf"]
FONT_BOLD_PATHS = [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"]
FONT_MONO = [r"C:\Windows\Fonts\consola.ttf", r"C:\Windows\Fonts\cour.ttf"]


def _register_fonts():
    body = bold = mono = "Helvetica"
    for p in FONT_PATHS:
        if os.path.exists(p):
            pdfmetrics.registerFont(TTFont("Body", p))
            body = "Body"
            bold = "Body-Bold"
            bp = next((b for b in FONT_BOLD_PATHS if os.path.exists(b)), p)
            pdfmetrics.registerFont(TTFont("Body-Bold", bp))
            break
    for p in FONT_MONO:
        if os.path.exists(p):
            pdfmetrics.registerFont(TTFont("Mono", p))
            mono = "Mono"
            break
    return body, bold, mono


BODY, BODY_BOLD, MONO = _register_fonts()


def _esc(text):
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _analyser_python(chemin):
    with open(chemin, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    fonctions = []
    classes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            args = [a.arg for a in node.args.args]
            doc = ast.get_docstring(node) or ""
            deco = [ast.unparse(d) if hasattr(ast, "unparse") else "" for d in node.decorator_list]
            fonctions.append({
                "nom": node.name, "ligne": node.lineno, "args": args,
                "doc": doc.strip(), "decorators": [d for d in deco if d],
                "fin": getattr(node, "end_lineno", node.lineno),
            })
        elif isinstance(node, ast.ClassDef):
            classes.append({
                "nom": node.name, "ligne": node.lineno,
                "doc": (ast.get_docstring(node) or "").strip(),
            })
    return source.splitlines(), fonctions, classes


def _analyser_js(chemin):
    with open(chemin, encoding="utf-8") as f:
        lignes = f.read().splitlines()
    fonctions = []
    for i, line in enumerate(lignes, 1):
        m = re.match(r"function\s+(\w+)\s*\(([^)]*)\)", line.strip())
        if m:
            fonctions.append({
                "nom": m.group(1), "ligne": i, "args": [a.strip() for a in m.group(2).split(",") if a.strip()],
                "doc": "", "decorators": [], "fin": i,
            })
        m2 = re.match(r"const\s+(\w+)\s*=\s*\(([^)]*)\)\s*=>", line.strip())
        if m2:
            fonctions.append({
                "nom": m2.group(1), "ligne": i, "args": [a.strip() for a in m2.group(2).split(",") if a.strip()],
                "doc": "Fonction fléchée (arrow function).", "decorators": [], "fin": i,
            })
    return lignes, fonctions, []


def _expliquer_ligne_python(line, no, ctx):
    s = line.strip()
    if not s:
        return "Ligne vide (séparation visuelle)."
    if s.startswith('"""') or s.startswith("'''") or (s.startswith("#") and not s.startswith("#!")):
        return f"Commentaire / docstring : {s.lstrip('#').strip()[:120]}"
    if s.startswith("#"):
        return f"Commentaire : {s[1:].strip()}"
    if s.startswith("@app.route"):
        return "Décorateur Flask : enregistre une route HTTP."
    if s.startswith("@app.after_request"):
        return "Hook Flask exécuté après chaque requête."
    if s.startswith("@socketio.on"):
        return "Écouteur d'événement WebSocket SocketIO."
    if s.startswith("@login_required"):
        return "Protège la route : admin connecté requis."
    if s.startswith("@csrf.exempt"):
        return "Exempte la route de la protection CSRF (API JSON agents)."
    if s.startswith("@limiter.limit"):
        return "Limite le nombre de requêtes (anti-abus / brute-force)."
    if s.startswith("@"):
        return f"Décorateur : {s[1:60]}"
    if s.startswith("import ") or s.startswith("from "):
        return "Import de module ou symbole Python."
    if s.startswith("def "):
        nom = s.split("(")[0].replace("def ", "")
        return f"Déclaration de la fonction {nom}()."
    if s.startswith("class "):
        return f"Déclaration de la classe {s.split()[1].split('(')[0]}."
    if s.startswith("return "):
        return "Retourne une valeur au appelant."
    if s.startswith("if ") or s.startswith("elif "):
        return "Condition : branche si la condition est vraie."
    if s.startswith("else:"):
        return "Branche alternative (sinon)."
    if s.startswith("for ") or s.startswith("while "):
        return "Boucle de répétition."
    if s.startswith("try:"):
        return "Début bloc try/except (gestion d'erreurs)."
    if s.startswith("except"):
        return "Capture une exception."
    if s.startswith("with "):
        return "Context manager (ressource ouverte/fermée automatiquement)."
    if "socketio.emit" in s:
        return "Émet un événement WebSocket vers les dashboards connectés."
    if "render_template" in s:
        return "Rend une page HTML Jinja2."
    if "jsonify" in s:
        return "Réponse JSON pour l'API."
    if "session[" in s or "session.get" in s:
        return "Lit/écrit la session Flask (utilisateur connecté)."
    if "database." in s:
        return "Appel à la couche base de données."
    if "scoring." in s:
        return "Appel au moteur de scoring."
    if "firebase_auth." in s:
        return "Appel au module Firebase."
    if "threat_intel." in s:
        return "Appel au module threat intelligence."
    if s.startswith("app.") or s.startswith("app.config"):
        return "Configuration de l'application Flask."
    if "=" in s and not s.startswith("if"):
        return "Affectation de variable ou constante."
    return "Instruction Python."


def _expliquer_ligne_js(line, no):
    s = line.strip()
    if not s:
        return "Ligne vide."
    if s.startswith("//"):
        return f"Commentaire : {s[2:].strip()}"
    if s.startswith("function "):
        return f"Déclaration fonction JavaScript {s.split('(')[0].replace('function ', '')}."
    if s.startswith("const ") or s.startswith("let ") or s.startswith("var "):
        if "=>" in s:
            return "Déclaration de fonction fléchée ou constante."
        return "Déclaration de constante/variable."
    if "fetch(" in s:
        return "Requête HTTP asynchrone vers le serveur."
    if "socket.on" in s or "socket.io" in s.lower():
        return "Gestion événement WebSocket temps réel."
    if "document." in s or "getElementById" in s:
        return "Manipulation du DOM (page HTML)."
    if "addEventListener" in s:
        return "Écouteur d'événement utilisateur (clic, saisie…)."
    if ".then(" in s or ".catch(" in s:
        return "Suite d'une promesse asynchrone."
    if "innerHTML" in s:
        return "Injection HTML dans un élément (alerte affichée)."
    return "Instruction JavaScript."


def _resume_fonction_py(fn, rel):
    nom, args, doc = fn["nom"], fn["args"], fn["doc"]
    dec = ", ".join(fn["decorators"]) if fn["decorators"] else ""
    resume = doc.split("\n")[0] if doc else _resume_auto(nom, rel)
    return resume, args, dec


def _resume_auto(nom, rel):
    resumes = {
        "main": "Point d'entrée : initialise et démarre le programme.",
        "login": "Page et traitement de connexion administrateur.",
        "login_2fa": "Vérification du code TOTP (2FA).",
        "logout": "Déconnexion et destruction de session.",
        "account": "Gestion du compte admin (mot de passe).",
        "dashboard": "Page principale de supervision des alertes.",
        "demo_alert": "Génère une alerte frauduleuse de démonstration.",
        "report": "Reçoit et traite un rapport d'agent (POST /report).",
        "score_event": "Analyse un événement et calcule score/niveau/raisons.",
        "insert_report": "Insère un rapport d'alerte en base.",
        "get_recent": "Récupère les alertes récentes.",
        "_conseil": "Associe un conseil de prévention aux raisons.",
        "init_db": "Crée les tables et applique migrations douces.",
        "envoyer": "Envoie un rapport au serveur central.",
        "surveiller_navigateur": "Surveille les liens ouverts dans le navigateur.",
        "url_a_analyser": "Filtre les URLs internes du navigateur.",
        "escapeHtml": "Échappe le HTML pour éviter les injections XSS.",
        "buildReport": "Construit l'élément HTML d'une alerte.",
        "renderStats": "Met à jour les compteurs et barres du dashboard.",
    }
    return resumes.get(nom, f"Fonction utilitaire « {nom} ».")


class DocPDF:
    def __init__(self):
        self.story = []
        base = getSampleStyleSheet()
        self.h1 = ParagraphStyle("h1", parent=base["Heading1"], fontName=BODY_BOLD,
                                 fontSize=14, textColor=colors.HexColor("#143C78"), spaceAfter=8)
        self.h2 = ParagraphStyle("h2", parent=base["Heading2"], fontName=BODY_BOLD,
                                 fontSize=11, textColor=colors.HexColor("#143C78"), spaceBefore=8, spaceAfter=4)
        self.body = ParagraphStyle("body", parent=base["Normal"], fontName=BODY, fontSize=9, leading=12)
        self.small = ParagraphStyle("small", parent=base["Normal"], fontName=BODY, fontSize=7.5, leading=10)
        self.code = ParagraphStyle("code", parent=base["Code"], fontName=MONO, fontSize=6.5, leading=8)
        self.fn = ParagraphStyle("fn", parent=base["Normal"], fontName=BODY, fontSize=8.5, leading=11,
                                 leftIndent=8, spaceAfter=3)

    def add_cover(self):
        self.story.append(Spacer(1, 4 * cm))
        self.story.append(Paragraph("DOCUMENTATION DU CODE", self.h1))
        self.story.append(Paragraph("MoMoGuard — explication fichier par fichier", self.body))
        self.story.append(Spacer(1, 0.5 * cm))
        self.story.append(Paragraph(f"Date : {date.today().strftime('%d/%m/%Y')}", self.body))
        self.story.append(Paragraph(
            "Ce document décrit chaque fichier source, chaque fonction déclarée "
            "et chaque ligne de code avec son rôle.", self.body))
        self.story.append(PageBreak())

    def add_toc(self):
        self.story.append(Paragraph("Table des matières", self.h1))
        for rel, desc in FICHIERS:
            self.story.append(Paragraph(f"• <b>{_esc(rel)}</b> — {_esc(desc)}", self.body))
        self.story.append(PageBreak())

    def add_fichier(self, rel, description):
        chemin = os.path.join(ROOT, rel.replace("/", os.sep))
        if not os.path.isfile(chemin):
            return
        self.story.append(Paragraph(f"Fichier : {rel}", self.h1))
        self.story.append(Paragraph(_esc(description), self.body))
        self.story.append(Spacer(1, 0.2 * cm))

        if rel.endswith(".py"):
            lignes, fonctions, classes = _analyser_python(chemin)
            expliquer = lambda l, n: _expliquer_ligne_python(l, n, rel)
        elif rel.endswith(".js"):
            lignes, fonctions, classes = _analyser_js(chemin)
            expliquer = _expliquer_ligne_js
        else:
            with open(chemin, encoding="utf-8") as f:
                lignes = f.read().splitlines()
            fonctions, classes = [], []
            expliquer = lambda l, n: "Ligne de code."

        if classes:
            self.story.append(Paragraph("Classes déclarées", self.h2))
            for c in classes:
                self.story.append(Paragraph(
                    f"<b>{_esc(c['nom'])}</b> (ligne {c['ligne']}) — {_esc(c['doc'] or 'Classe Python.')}",
                    self.fn))

        if fonctions:
            self.story.append(Paragraph("Fonctions déclarées", self.h2))
            for fn in fonctions:
                resume, args, dec = _resume_fonction_py(fn, rel)
                arg_s = ", ".join(fn["args"]) if fn["args"] else ""
                dec_s = f" [{dec}]" if dec else ""
                self.story.append(Paragraph(
                    f"<b>{_esc(fn['nom'])}</b>({ _esc(arg_s) }) — ligne {fn['ligne']}{_esc(dec_s)}",
                    self.fn))
                self.story.append(Paragraph(f"→ {_esc(resume)}", self.small))
                if fn["doc"] and "\n" in fn["doc"]:
                    for ligne_doc in fn["doc"].split("\n")[1:3]:
                        if ligne_doc.strip():
                            self.story.append(Paragraph(f"  {_esc(ligne_doc.strip())}", self.small))

        self.story.append(Spacer(1, 0.15 * cm))
        self.story.append(Paragraph("Explication ligne par ligne", self.h2))

        batch = []
        for i, line in enumerate(lignes, 1):
            exp = expliquer(line, i)
            code_txt = line.replace("\t", "    ")[:95]
            if len(line) > 95:
                code_txt += "…"
            batch.append([str(i), code_txt, exp])
            if len(batch) >= 18:
                self._table_lignes(batch)
                batch = []
        if batch:
            self._table_lignes(batch)

        self.story.append(PageBreak())

    def _table_lignes(self, rows):
        data = [["L.", "Code", "Explication"]]
        for no, code, exp in rows:
            data.append([no, code, exp])
        t = Table(data, colWidths=[1.1 * cm, 7.2 * cm, 8.2 * cm], repeatRows=1)
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), BODY_BOLD),
            ("FONTNAME", (0, 1), (0, -1), MONO),
            ("FONTNAME", (1, 1), (1, -1), MONO),
            ("FONTNAME", (2, 1), (2, -1), BODY),
            ("FONTSIZE", (0, 0), (-1, -1), 6.5),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E6F0FA")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        self.story.append(t)
        self.story.append(Spacer(1, 0.1 * cm))


def main():
    doc = SimpleDocTemplate(
        OUTPUT, pagesize=A4,
        leftMargin=1.2 * cm, rightMargin=1.2 * cm,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm,
    )
    pdf = DocPDF()
    pdf.add_cover()
    pdf.add_toc()
    for rel, desc in FICHIERS:
        pdf.add_fichier(rel, desc)

    # Annexe : fichiers complémentaires (résumé sans ligne par ligne)
    pdf.story.append(Paragraph("Annexe — Autres fichiers du projet", pdf.h1))
    annexes = [
        ("server/templates/", "Pages HTML Jinja2 : base (layout), dashboard, login, login_2fa, account, agents, users, user_detail, settings, consent, consents, audit, twofa_setup."),
        ("server/static/style.css", "Feuille de styles CSS : thème sombre/clair, cartes stats, alertes, graphiques, formulaires."),
        ("tests/", "Suite pytest : scoring, report, users, 2FA, audit, security, settings, threat_intel, demo_conseil, windows_agent."),
        ("tests/conftest.py", "Fixtures pytest : instance Flask isolée sur SQLite temporaire."),
        ("evaluation/dataset_evaluation.json", "48 messages étiquetés pour benchmark du moteur."),
        ("requirements.txt", "Dépendances Python (Flask, SQLAlchemy, Firebase, pytest…)."),
        ("Makefile", "Raccourcis : install, run, test, seed, backup."),
    ]
    for chemin, desc in annexes:
        pdf.story.append(Paragraph(f"<b>{_esc(chemin)}</b>", pdf.h2))
        pdf.story.append(Paragraph(_esc(desc), pdf.body))
        pdf.story.append(Spacer(1, 0.15 * cm))

    doc.build(pdf.story)
    print(f"PDF généré : {OUTPUT}")


if __name__ == "__main__":
    main()
