# Scénario de démo — Soutenance MoMoGuard

Durée cible : **4 à 5 minutes**, après la slide 11 du deck. Répète-le au moins une fois en entier avant la soutenance, chrono en main.

---

## 1. Checklist AVANT la soutenance (la veille + 1 h avant)

### Matériel

- [ ] PC portable chargé + chargeur
- [ ] Téléphone Android **protégé** (app MoMoGuard installée, compte approuvé) — chargé
- [ ] Second téléphone (ou SIM) pour **envoyer** le SMS frauduleux — avec crédit SMS
- [ ] Câble/adaptateur vidéo pour le projecteur de la salle
- [ ] PC et téléphone sur le **même réseau Wi-Fi** (ou partage de connexion du téléphone → le PC s'y connecte)

### Serveur (sur le PC)

- [ ] `python run.py` — dashboard sur http://127.0.0.1:5000
- [ ] Connexion admin OK (`admin` / ton mot de passe) + code 2FA si activée — **prépare ton app TOTP**
- [ ] `python scripts/seed_demo.py` si tu veux un dashboard déjà peuplé (plus vivant qu'un dashboard vide)
- [ ] Note l'**adresse IP locale du PC** (`ipconfig` → ex. `192.168.1.20`) — c'est elle que l'app doit utiliser

### Téléphone protégé

- [ ] Dans l'app : URL du serveur = `http://192.168.1.20:5000` (l'IP du PC, PAS 127.0.0.1)
- [ ] Connexion Firebase OK, compte **approuvé** côté admin (page Utilisateurs)
- [ ] Protection activée (bouton ON), permissions SMS et notifications accordées
- [ ] **Test complet la veille** : envoyer un SMS de test et vérifier que l'alerte arrive

### Onglets ouverts sur le PC (dans cet ordre)

1. Dashboard (page d'accueil)
2. Page Analyzer (analyse manuelle)
3. Page Audit (si un juré pose une question sur la traçabilité)

---

## 2. Le SMS frauduleux à envoyer (à préparer en brouillon sur le 2e téléphone)

> URGENT : votre compte Orange Money sera bloque. Cliquez http://0range-money.xyz pour reactiver

Pourquoi celui-là : il déclenche **5 règles** (domaine sosie en homoglyphes +35, TLD .xyz +15, vocabulaire d'arnaque +32, urgence + lien +12, http +5) → **score 99, niveau ÉLEVÉ**. Parfait pour montrer l'explicabilité.

Message de secours n° 2 (autre famille d'attaque — faux agent) :

> Bonjour, je suis agent Airtel Money. Confirmez votre code PIN pour valider votre compte

---

## 3. Déroulé minuté

| Temps | Action | Ce que tu dis au jury |
|---|---|---|
| 0:00 | Montrer le dashboard à l'écran, téléphone protégé visible (idéalement filmé ou tenu vers le jury). | « Voici le tableau de bord de supervision. Le téléphone que vous voyez est protégé par l'agent MoMoGuard. » |
| 0:30 | Depuis le 2e téléphone, envoyer le SMS frauduleux préparé. | « J'envoie maintenant un vrai SMS d'arnaque, comme en reçoivent chaque jour les utilisateurs de Mobile Money. » |
| 1:00 | L'alerte apparaît **en direct** sur le dashboard (WebSocket, sans recharger). Cliquer dessus. | « L'agent a intercepté le message et le serveur l'a analysé : score 99, niveau élevé. » |
| 1:30 | **Moment clé** : lire les raisons une par une. | « Et surtout, le système explique sa décision : domaine sosie “0range” écrit avec un zéro, extension .xyz, vocabulaire d'urgence… Rien n'est une boîte noire. » |
| 2:30 | Montrer le téléphone protégé : la **notification push FCM** est arrivée. | « L'utilisateur, lui, a été averti immédiatement sur son téléphone. » |
| 3:00 | Ouvrir l'Analyzer, coller le 2e message (faux agent), lancer l'analyse. | « Le moteur couvre d'autres familles d'attaques — ici, un faux agent qui demande un code PIN. » |
| 4:00 | (Optionnel si le temps le permet) Montrer la page Stats ou Audit. | « Chaque action est tracée, et les statistiques permettent de suivre les tendances. » |
| 4:30 | Revenir aux slides (conclusion). | « Voilà la chaîne complète : du SMS à l'alerte, en temps réel. » |

---

## 4. Plans B (dans l'ordre, si quelque chose casse)

| Panne | Solution | Impact |
|---|---|---|
| Le SMS n'arrive pas / pas de réseau mobile | Bouton **« Simuler une alerte »** du dashboard (route `/demo`) : insère une alerte réaliste et la pousse en WebSocket + FCM. | Quasi nul — le jury voit le même flux temps réel. Dis-le honnêtement : « je simule l'envoi, le reste de la chaîne est réel ». |
| Le téléphone ne remonte rien (Wi-Fi, IP…) | Page **Analyzer** : coller le SMS et l'analyser en direct. | Tu montres le moteur et l'explicabilité, sans la capture. |
| Le Wi-Fi de la salle bloque tout | Partage de connexion du téléphone → le PC se connecte au hotspot du téléphone. À tester la veille. | Aucun. |
| Le serveur plante | `python run.py` relance en 5 secondes ; la base SQLite garde tout. | Faible. |
| Panne totale | Captures d'écran de secours (fais-les AUJOURD'HUI pendant ta répétition : dashboard avec alerte, détail des raisons, notification sur le téléphone). | Tu racontes la démo sur images. |

---

## 5. Questions probables du jury pendant la démo

- **« Et si le fraudeur écrit sans faute et sans lien ? »** → C'est la limite des règles statiques (slide 12) ; le combo de règles 8-14 couvre les attaques sans lien (SIM swap, faux agent, remboursement…). Perspective : hybridation avec du ML.
- **« Vous lisez tous les SMS des gens ? »** → Non : consentement explicite et révocable, l'endpoint `/report` refuse tout appareil non consenti, et tout est journalisé (page Audit à montrer).
- **« Pourquoi des règles et pas du machine learning ? »** → Explicabilité (chaque alerte est justifiable devant l'utilisateur), pas besoin de gros dataset, fonctionne hors ligne côté serveur. Le ML est la perspective, pas le point de départ.
- **« 48 messages, c'est peu, non ? »** → Oui, limite assumée ; le benchmark est reproductible (script + dataset versionnés) et conçu pour être étendu.
