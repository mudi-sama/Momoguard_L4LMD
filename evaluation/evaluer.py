"""Évaluation chiffrée du moteur de détection MoMoGuard.

Fait passer un jeu de messages étiquetés dans le moteur de scoring et calcule
le taux de détection, le taux de faux positifs, la précision, le rappel, le
F1-score et l'exactitude, avec matrice de confusion et figures.

Usage : python evaluation/evaluer.py
"""
import os  # Chemins absolus vers le dataset et les sorties
import sys  # Modification du PYTHONPATH pour importer server
import json  # Chargement du jeu de données étiqueté

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # Racine projet dans sys.path
from server import scoring  # Moteur de scoring MoMoGuard à évaluer

ICI = os.path.dirname(os.path.abspath(__file__))  # Répertoire evaluation/ (dataset, rapports, figures)
SEUILS = (25, 55)  # seuils par défaut (moyen, eleve)


def predire(text, etype):
    _, level, _ = scoring.score_event(etype, text, {}, SEUILS)  # Score sans métadonnées, récupère le niveau
    return "fraude" if level in ("moyen", "eleve") else "legitime"  # Fraude si niveau moyen ou élevé


def main():
    with open(os.path.join(ICI, "dataset_evaluation.json"), encoding="utf-8") as f:  # Ouvre le jeu de test
        data = json.load(f)  # Liste de messages avec text, type et label

    tp = fp = tn = fn = 0  # Compteurs matrice de confusion : VP, FP, VN, FN
    erreurs = []  # Liste des cas mal classés pour analyse critique
    for item in data:  # Parcourt chaque message étiqueté
        pred = predire(item["text"], item.get("type", "sms"))  # Prédiction du moteur (fraude ou legitime)
        vrai = item["label"]  # Étiquette de référence du dataset
        if vrai == "fraude" and pred == "fraude":  # Vrai positif : fraude correctement détectée
            tp += 1
        elif vrai == "fraude" and pred == "legitime":  # Faux négatif : fraude manquée
            fn += 1
            erreurs.append(("Faux negatif (fraude manquee)", item["text"]))  # Enregistre pour le rapport
        elif vrai == "legitime" and pred == "fraude":  # Faux positif : alerte injustifiée
            fp += 1
            erreurs.append(("Faux positif (fausse alerte)", item["text"]))  # Enregistre pour le rapport
        else:  # vrai legitime et pred legitime
            tn += 1  # Vrai négatif : message légitime correctement ignoré

    total = tp + fp + tn + fn  # Nombre total de messages évalués
    rappel = tp / (tp + fn) if (tp + fn) else 0      # taux de detection
    tfp = fp / (fp + tn) if (fp + tn) else 0          # taux de faux positifs
    precision = tp / (tp + fp) if (tp + fp) else 0  # Part des alertes fraude qui sont correctes
    f1 = 2 * precision * rappel / (precision + rappel) if (precision + rappel) else 0  # Moyenne harmonique précision/rappel
    exactitude = (tp + tn) / total if total else 0  # Proportion de classifications correctes

    print("=" * 56)  # Séparateur visuel
    print(" Évaluation du moteur de détection MoMoGuard")  # Titre du rapport console
    print("=" * 56)
    print(f" Échantillon         : {total} messages ({tp+fn} fraude, {tn+fp} légitime)")  # Taille et répartition
    print(f" Seuils (moyen/élevé): {SEUILS[0]} / {SEUILS[1]}")  # Seuils utilisés pour la prédiction
    print("-" * 56)
    print(f" Vrais positifs  (TP): {tp:3d}    Faux negatifs (FN): {fn:3d}")  # Ligne VP / FN
    print(f" Vrais negatifs  (TN): {tn:3d}    Faux positifs (FP): {fp:3d}")  # Ligne VN / FP
    print("-" * 56)
    print(f" Taux de detection (rappel)  : {rappel:6.1%}")  # Sensibilité du détecteur
    print(f" Taux de faux positifs       : {tfp:6.1%}")  # Proportion de fausses alertes sur légitimes
    print(f" Precision                   : {precision:6.1%}")  # Fiabilité des alertes fraude
    print(f" F1-score                    : {f1:6.1%}")  # Compromis précision / rappel
    print(f" Exactitude (accuracy)       : {exactitude:6.1%}")  # Taux global de bonnes réponses
    print("=" * 56)
    if erreurs:  # Affiche les erreurs s'il y en a
        print(" Erreurs (analyse critique) :")
        for kind, txt in erreurs:  # Détail de chaque mauvaise classification
            print(f"  - {kind}: {txt[:60]}...")  # Tronque le texte pour la lisibilité console

    _ecrire_rapport(total, tp, fp, tn, fn, rappel, tfp, precision, f1, exactitude, erreurs)  # Génère resultats.md
    _figures(tp, fp, tn, fn, rappel, tfp, precision, f1, exactitude)  # Génère les graphiques PNG


def _ecrire_rapport(total, tp, fp, tn, fn, rappel, tfp, precision, f1, exactitude, erreurs):
    lignes = [  # Contenu Markdown du rapport d'évaluation
        "# Évaluation chiffrée du moteur de détection MoMoGuard\n",
        "## Méthodologie\n",
        f"Un jeu de **{total} messages** étiquetés ({tp+fn} frauduleux, {tn+fp} légitimes), "
        "représentatifs du contexte Mobile Money en RDC, a été soumis au moteur de scoring. "
        f"Un message est considéré comme détecté lorsque son niveau atteint « moyen » ou « élevé » "
        f"(seuils {SEUILS[0]}/{SEUILS[1]}).\n",
        "## Matrice de confusion\n",
        "| | Prédit fraude | Prédit légitime |",
        "|---|---|---|",
        f"| **Réel fraude** | {tp} (VP) | {fn} (FN) |",
        f"| **Réel légitime** | {fp} (FP) | {tn} (VN) |\n",
        "## Résultats\n",
        "| Métrique | Valeur |",
        "|---|---|",
        f"| Taux de détection (rappel) | {rappel:.1%} |",
        f"| Taux de faux positifs | {tfp:.1%} |",
        f"| Précision | {precision:.1%} |",
        f"| F1-score | {f1:.1%} |",
        f"| Exactitude | {exactitude:.1%} |\n",
    ]
    if erreurs:  # Section optionnelle listant les erreurs de classification
        lignes.append("## Analyse critique des erreurs\n")
        for kind, txt in erreurs:  # Une puce par erreur
            lignes.append(f"- **{kind}** : « {txt} »")
    with open(os.path.join(ICI, "resultats.md"), "w", encoding="utf-8") as f:  # Écrit le fichier Markdown
        f.write("\n".join(lignes) + "\n")  # Joint les lignes avec retours à la ligne


def _figures(tp, fp, tn, fn, rappel, tfp, precision, f1, exactitude):
    import matplotlib  # Backend graphique (import différé pour accélérer le démarrage)
    matplotlib.use("Agg")  # Rendu sans interface graphique (serveur / CI)
    import matplotlib.pyplot as plt  # API de tracé

    # Matrice de confusion
    fig, ax = plt.subplots(figsize=(5, 4))  # Figure 5×4 pouces pour la matrice
    mat = [[tp, fn], [fp, tn]]  # Grille 2×2 : lignes=réel, colonnes=prédit
    ax.imshow(mat, cmap="Purples")  # Heatmap violet selon les effectifs
    ax.set_xticks([0, 1]); ax.set_xticklabels(["Prédit\nfraude", "Prédit\nlégitime"])  # Libellés colonnes
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Réel\nfraude", "Réel\nlégitime"])  # Libellés lignes
    for i in range(2):  # Parcourt les lignes de la matrice
        for j in range(2):  # Parcourt les colonnes
            ax.text(j, i, mat[i][j], ha="center", va="center", fontsize=18,  # Affiche la valeur dans chaque cellule
                    color="black")
    ax.set_title("Matrice de confusion — MoMoGuard")  # Titre du graphique
    fig.tight_layout()  # Ajuste les marges automatiquement
    fig.savefig(os.path.join(ICI, "confusion_matrix.png"), dpi=130)  # Export PNG haute résolution

    # Métriques
    fig2, ax2 = plt.subplots(figsize=(6, 4))  # Deuxième figure pour les barres de performance
    noms = ["Détection", "Précision", "F1-score", "Exactitude"]  # Libellés des barres
    vals = [rappel, precision, f1, exactitude]  # Valeurs correspondantes (0–1)
    ax2.bar(noms, [v * 100 for v in vals], color="#6c63ff")  # Barres en pourcentage, couleur MoMoGuard
    ax2.set_ylim(0, 100); ax2.set_ylabel("%")  # Axe Y en pourcentage
    ax2.set_title("Performances du moteur de détection")  # Titre du graphique métriques
    for i, v in enumerate(vals):  # Étiquette au-dessus de chaque barre
        ax2.text(i, v * 100 + 1, f"{v:.0%}", ha="center", fontsize=11)  # Pourcentage formaté
    fig2.tight_layout()  # Ajuste les marges
    fig2.savefig(os.path.join(ICI, "metriques.png"), dpi=130)  # Export PNG des métriques
    print(" Figures écrites : evaluation/confusion_matrix.png, evaluation/metriques.png")  # Confirmation console


if __name__ == "__main__":  # Exécution directe du script d'évaluation
    main()  # Lance l'évaluation complète
