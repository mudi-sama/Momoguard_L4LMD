# Évaluation chiffrée du moteur de détection MoMoGuard

## Méthodologie

Un jeu de **48 messages** étiquetés (26 frauduleux, 22 légitimes), représentatifs du contexte Mobile Money en RDC, a été soumis au moteur de scoring. Un message est considéré comme détecté lorsque son niveau atteint « moyen » ou « élevé » (seuils 25/55).

## Matrice de confusion

| | Prédit fraude | Prédit légitime |
|---|---|---|
| **Réel fraude** | 25 (VP) | 1 (FN) |
| **Réel légitime** | 0 (FP) | 22 (VN) |

## Résultats

| Métrique | Valeur |
|---|---|
| Taux de détection (rappel) | 96.2% |
| Taux de faux positifs | 0.0% |
| Précision | 100.0% |
| F1-score | 98.0% |
| Exactitude | 97.9% |

## Analyse critique des erreurs

- **Faux negatif (fraude manquee)** : « Promo speciale : envoyez 10$ et recevez 500$ sur votre compte M-Pesa aujourd'hui. »
