# SMS de test — niveaux moyen et élevé

Messages à envoyer (SMS, WhatsApp, ou collage) pour vérifier MoMoGuard en démo / soutenance.

**Seuils par défaut** : moyen ≥ **25**, élevé ≥ **55** (réglables dans le dashboard → Paramètres).

**Comment tester**
1. Installer MoMoGuard sur le téléphone cible (compte approuvé, monitoring actif).
2. Envoyer le SMS **depuis un autre numéro** vers ce téléphone (ou coller le texte dans un canal capturé).
3. Vérifier : notification locale + alerte dans l’app + rapport dans le dashboard.

Les scores ci-dessous ont été mesurés avec `server/scoring.py` (seuils 25 / 55).

---

## Niveau moyen (score 25–54)

Signaux suspects, sans cumul suffisant pour l’alerte maximale. Utile pour montrer la **notification modérée**.

### 1. Lien raccourci (score ≈ 25)
```
Promo forfait. Infos: http://bit.ly/promoRDC
```

### 2. Lien TinyURL (score ≈ 25)
```
Mise a jour disponible http://tinyurl.com/maj-app
```

### 3. Lien goo.gl + mot « reactivez » (score ≈ 25)
```
Probleme de paiement. Reactivez: http://goo.gl/momopay
```

### 4. Extension .click + « expire » + « cliquez » (score ≈ 40)
```
Votre abonnement expire. Cliquez http://offre.click pour en savoir plus.
```

### 5. Vocabulaire d’arnaque sans lien (score ≈ 49)
```
Felicitations, promotion speciale. Cliquez pour verifier maintenant.
```

### 6. Demande de code OTP (score ≈ 38) — arnaque réelle, score « moyen »
```
Envoie-moi le code de confirmation que tu viens de recevoir, c est pour la transaction.
```

### 7. Demande de mot de passe (score ≈ 46) — arnaque réelle, score « moyen »
```
Votre compte est bloque. Envoyez votre mot de passe pour le reactiver immediatement.
```

### 8. Faux remboursement (score ≈ 25)
```
J ai envoye 200$ par erreur sur votre compte, merci de me rembourser au plus vite.
```

### 9. Loterie + frais (score ≈ 41) — souvent « moyen » sans lien / USSD
```
Vous avez gagne 5.000.000 FC a la tombola Vodacom ! Envoyez 50$ de frais pour recevoir.
```

---

## Niveau élevé (score ≥ 55)

Combinaisons fortes (phishing d’opérateur, USSD, SIM swap, faux agent…). Utile pour montrer **son + vibration** et l’alerte critique.

### 1. Phishing Orange + domaine sosie + urgence (score ≈ 83)
```
URGENT: votre compte Orange Money sera suspendu. Reactivez sur http://0range-money.tk
```

### 2. Domaine sosie Vodacom (score ≈ 63)
```
Securite Vodacom: activite suspecte. Confirmez http://v0dacom-secure.tk
```

### 3. Domaine sosie Airtel + urgence (score ≈ 63)
```
Cher client, verifiez votre compte ici http://airtel-verif.xyz sinon blocage sous 24h
```

### 4. Phishing Orange + TLD suspect (score ≈ 63)
```
ALERTE: connexion inconnue. Cliquez http://orange-money.cm-secure.xyz pour securiser.
```

### 5. SIM swap / code PUK (score ≈ 55)
```
M-Pesa: votre carte SIM va etre remplacee. Communiquez votre code PUK pour confirmer.
```

### 6. Faux agent opérateur (score ≈ 55)
```
Bonjour, je suis agent Airtel Money. Composez ce code et donnez-le pour valider votre compte.
```

### 7. Agent + code USSD (score ≈ 80)
```
Agent Vodacom: composez *144*1# et envoyez le code recu a ce numero.
```

### 8. Gain + USSD (score ≈ 88) — très fort pour la démo
```
Votre numero a gagne ! Composez *144*1# et envoyez le code recu a ce numero.
```

### 9. Frais de déblocage + USSD (score ≈ 63)
```
Vous devez payer 5$ de frais de deblocage. Composez *123# et confirmez le code.
```

### 10. Loterie + lien raccourci (score ≈ 61)
```
Felicitations ! Cliquez https://bit.ly/3xPromoo pour reclamer votre bonus de 100$
```

---

## Contrôles négatifs (doivent rester faibles)

À envoyer pour montrer que MoMoGuard **ne crie pas** sur un SMS légitime.

```
Vous avez recu 50.000 FC de Jean Mukendi. Nouveau solde: 175.000 FC.
```

```
Votre code de verification Orange Money est 4821. Ne le communiquez a personne.
```

```
Salut, on se voit demain a 14h au campus ?
```

---

## Mini scénario démo (3 minutes)

| Ordre | Message | Niveau attendu | À montrer |
|------|---------|----------------|-----------|
| 1 | Contrôle négatif (solde) | faible | Pas d’alerte agressive |
| 2 | Lien `bit.ly` (moyen §1) | moyen | Notif modérée |
| 3 | Phishing `0range-money.tk` (élevé §1) | élevé | Son / vibration + dashboard |
| 4 | SIM swap PUK (élevé §5) | élevé | Raison « SIM swap » dans le rapport |

---

## Astuces

- **Copier-coller tel quel** : accents optionnels (le moteur normalise).
- Un même texte peut changer de niveau si tu modifies les **seuils** dans Paramètres.
- Pour forcer un « élevé » en démo : privilégier **domaine sosie d’opérateur** (`.tk` / `.xyz`) ou **code USSD** `*...*#`.
- Les liens sont fictifs : ne pas les ouvrir ; ils servent uniquement à déclencher les règles.
