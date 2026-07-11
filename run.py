"""Point d'entrée MoMoGuard — lance le serveur central."""
from server.app import main  # Importe la fonction qui initialise et démarre Flask + SocketIO

if __name__ == "__main__":  # Vrai uniquement si on exécute : python run.py
    main()  # Lance le serveur sur http://127.0.0.1:5000
