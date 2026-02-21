Prérequis

- Python 3.11+

- MongoDB Atlas

- Ollama installé

- .env contenant les variables ci-dessous
  
MONGODB_CONNECT_URI=your_mongodb_connection_string
SECRET_KEY=your_secret_key

Installation

Dans un premier terminal  exécuter les commandes ci-dessous

- cd PFE-backend
- pip install fastapi uvicorn "passlib[bcrypt]" motor python-dotenv pandas python-multipart
- pip install "python-jose[cryptography]"
- pip install ollama

Lancement du projet
- uvicorn api:app --reload

Backend accessible sur :

- http://127.0.0.1:8000

Lancement Ollama

- Dans un autre terminal lancé  : ollama run llama3

Puis fermer le prompt interactif, le serveur reste actif.





