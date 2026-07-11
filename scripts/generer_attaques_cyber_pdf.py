"""Génère le PDF : types d'attaques cyber couverts par MoMoGuard."""
import os
from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(ROOT, "ATTAQUES_CYBER_MOMOGUARD.pdf")

FONT_PATHS = [r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\arial.ttf"]
FONT_BOLD_PATHS = [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"]


def _register_fonts():
    body, bold = "Helvetica", "Helvetica-Bold"
    for p in FONT_PATHS:
        if os.path.exists(p):
            pdfmetrics.registerFont(TTFont("Body", p))
            body = "Body"
            bp = next((b for b in FONT_BOLD_PATHS if os.path.exists(b)), p)
            pdfmetrics.registerFont(TTFont("Body-Bold", bp))
            bold = "Body-Bold"
            break
    return body, bold


BODY, BODY_BOLD = _register_fonts()


def _esc(text):
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _styles():
    return {
        "title": ParagraphStyle(
            "title", fontName=BODY_BOLD, fontSize=20, leading=26,
            alignment=TA_CENTER, spaceAfter=14, textColor=colors.HexColor("#1a365d"),
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontName=BODY, fontSize=11, leading=15,
            alignment=TA_CENTER, spaceAfter=24, textColor=colors.HexColor("#4a5568"),
        ),
        "h1": ParagraphStyle(
            "h1", fontName=BODY_BOLD, fontSize=14, leading=18,
            spaceBefore=16, spaceAfter=8, textColor=colors.HexColor("#2c5282"),
        ),
        "h2": ParagraphStyle(
            "h2", fontName=BODY_BOLD, fontSize=11, leading=14,
            spaceBefore=10, spaceAfter=6, textColor=colors.HexColor("#2d3748"),
        ),
        "body": ParagraphStyle(
            "body", fontName=BODY, fontSize=10, leading=14,
            alignment=TA_JUSTIFY, spaceAfter=6,
        ),
        "bullet": ParagraphStyle(
            "bullet", fontName=BODY, fontSize=10, leading=14,
            leftIndent=14, spaceAfter=4, bulletIndent=0,
        ),
        "footer": ParagraphStyle(
            "footer", fontName=BODY, fontSize=8, leading=10,
            alignment=TA_CENTER, textColor=colors.grey,
        ),
    }


def _table(headers, rows, col_widths):
    data = [headers] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), BODY_BOLD),
        ("FONTNAME", (0, 1), (-1, -1), BODY),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def generer():
    s = _styles()
    story = []

    story.append(Paragraph("MoMoGuard — Types d'attaques cyber couvertes", s["title"]))
    story.append(Paragraph(
        f"Document de référence sécurité · Mémoire L4 Cybersécurité · {date.today().strftime('%d/%m/%Y')}",
        s["subtitle"],
    ))

    story.append(Paragraph(
        "MoMoGuard agit sur deux niveaux : la <b>détection de fraudes Mobile Money</b> "
        "(cœur du projet) et la <b>sécurité technique</b> de la plateforme (serveur + agents Android/Windows).",
        s["body"],
    ))

    # --- Section 1 ---
    story.append(Paragraph("1. Fraudes ciblant l'utilisateur Mobile Money", s["h1"]))
    story.append(Paragraph(
        "Mission principale du projet : protéger les victimes potentielles d'arnaques liées au mobile money en RDC.",
        s["body"],
    ))
    story.append(_table(
        ["Type d'attaque", "Réaction de MoMoGuard"],
        [
            ["Smishing / phishing par SMS", "Agent Android + scoring (mots-clés : urgent, code PIN, réactivez…)"],
            ["Hameçonnage par notification", "NotificationCaptureService + filtre local avant envoi"],
            ["Phishing par lien frauduleux", "Détection URLs, TLD suspects (.tk, .xyz), raccourcisseurs"],
            ["Typosquatting / domaines sosies", "Homoglyphes (0range, v0dacom) vs domaines officiels"],
            ["Faux agent opérateur", "Détection « agent Orange », demande de code, confirmez identité"],
            ["SIM swap / remplacement SIM", "Détection PUK, nouvelle SIM, carte SIM remplacée"],
            ["Vol de code OTP / PIN", "Détection demandes de partage de code, OTP, mot de passe"],
            ["Arnaque au gain / loterie", "Félicitations, vous avez gagné, frais pour récupérer"],
            ["Arnaque au transfert par erreur", "Envoyé par erreur, renvoyez l'argent"],
            ["Fraude USSD", "Codes *123# dans le presse-papier (agent Windows)"],
            ["Liens malveillants connus", "Google Safe Browsing (si clé API configurée)"],
            ["Fichiers dangereux", "Surveillance Téléchargements (.exe, .apk, .scr…) — Windows"],
            ["Phishing navigateur", "Historique Chrome/Edge/Firefox/Brave — agent Windows"],
        ],
        [5.5 * cm, 11.5 * cm],
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "<b>Mécanisme :</b> score 0–100 → niveau faible / moyen / élevé → alerte admin + notification push si danger élevé.",
        s["body"],
    ))

    # --- Section 2 ---
    story.append(PageBreak())
    story.append(Paragraph("2. Attaques contre la plateforme MoMoGuard", s["h1"]))
    story.append(Paragraph(
        "Contrôles OWASP appliqués sur le serveur Flask et les API.",
        s["body"],
    ))
    story.append(_table(
        ["Type d'attaque", "Protection en place"],
        [
            ["Force brute (login admin)", "Rate limiting : 10 tentatives/min sur /login et /login/2fa"],
            ["Vol de session admin", "Cookie HttpOnly, SameSite=Lax, Secure (HTTPS), expiration 8 h"],
            ["CSRF", "CSRFProtect sur tous les formulaires HTML"],
            ["Accès non autorisé au dashboard", "@login_required + WebSocket refusé sans session admin"],
            ["Usurpation d'identité client", "Vérification cryptographique jeton Firebase (verify_id_token)"],
            ["Faux rapports / spam d'alertes", "Agent pré-enregistré + jeton obligatoire + rate limit /report"],
            ["Spoofing d'UID", "UID extrait du jeton Firebase, pas du champ libre uid"],
            ["Injection SQL", "SQLAlchemy ORM (requêtes paramétrées)"],
            ["XSS", "Échappement Jinja2 + escapeHtml() JS + en-têtes CSP"],
            ["Clickjacking", "X-Frame-Options: DENY"],
            ["MIME sniffing", "X-Content-Type-Options: nosniff"],
            ["Comptes non approuvés", "Workflow pending → approved ; refus si non validé"],
            ["Agents compromis", "Blocage admin + refus des rapports"],
            ["Abus API Firebase", "Rate limiting sur /api/auth/firebase, /api/my-reports, /api/fcm-token"],
            ["DoS applicatif", "Limite taille content / metadata sur /report"],
            ["Désactivation malveillante 2FA", "Re-auth mot de passe + code TOTP requis"],
        ],
        [5.5 * cm, 11.5 * cm],
    ))

    # --- Section 3 ---
    story.append(Spacer(1, 16))
    story.append(Paragraph("3. Attaques côté mobile (agent Android)", s["h1"]))
    story.append(_table(
        ["Type d'attaque", "Protection"],
        [
            ["Extraction de jetons (backup, root)", "EncryptedSharedPreferences + allowBackup=false"],
            ["Interception réseau (MITM)", "HTTPS obligatoire en release ; HTTP en debug uniquement"],
            ["Capture d'écran des alertes", "FLAG_SECURE sur Paramètres, MFA, Alertes"],
            ["Reverse engineering APK", "R8/ProGuard activé en release"],
            ["Surveillance non consentie", "Consentement explicite + service foreground visible"],
        ],
        [5.5 * cm, 11.5 * cm],
    ))

    # --- Section 4 ---
    story.append(PageBreak())
    story.append(Paragraph("4. Limites — ce que MoMoGuard ne couvre pas", s["h1"]))
    story.append(Paragraph(
        "À mentionner honnêtement dans le mémoire pour démontrer une analyse de risque complète.",
        s["body"],
    ))
    story.append(_table(
        ["Attaque", "Pourquoi non couverte"],
        [
            ["DDoS réseau (volume massif)", "Pas de WAF/CDN ; rate limit en mémoire uniquement"],
            ["MITM sans HTTPS en production", "Possible si mal déployé (certificat absent)"],
            ["Malware avancé / spyware", "MoMoGuard n'est pas un antivirus"],
            ["Ingénierie sociale en face-à-face", "Pas de détection hors messages numériques"],
            ["Phishing personnalisé sans mots-clés", "Scoring par règles contournable"],
            ["Attaque sur Firebase/Google", "Dépendance à des tiers"],
            ["Accès physique téléphone déverrouillé", "Hors périmètre"],
            ["APT / ransomware", "Hors périmètre d'un agent de détection SMS"],
        ],
        [5.5 * cm, 11.5 * cm],
    ))

    # --- Section 5 ---
    story.append(Spacer(1, 20))
    story.append(Paragraph("5. Conclusion pour le mémoire", s["h1"]))
    story.append(Paragraph(
        "<i>MoMoGuard est un système de détection et d'alerte orienté vers les arnaques Mobile Money "
        "(smishing, phishing par lien, SIM swap, faux agents, arnaques au gain et au remboursement). "
        "Sur le plan technique, il intègre des contrôles contre les attaques web classiques "
        "(brute force, CSRF, usurpation d'identité, injection SQL, accès non autorisé). "
        "Il ne constitue pas une solution de sécurité périmétrique complète, mais une couche de détection "
        "consentie couplée à une plateforme de supervision sécurisée.</i>",
        s["body"],
    ))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f"Généré automatiquement · Projet MoMoGuard · {date.today().isoformat()}",
        s["footer"],
    ))

    doc = SimpleDocTemplate(
        OUTPUT, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title="MoMoGuard — Attaques cyber couvertes",
        author="MoMoGuard",
    )
    doc.build(story)
    print(f"PDF généré : {OUTPUT}")
    return OUTPUT


if __name__ == "__main__":
    generer()
