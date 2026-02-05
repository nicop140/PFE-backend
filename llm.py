import ollama as ollama_lib
import re
from datetime import datetime
from ollama import Client

TOPOLOGY = """
ARCHITECTURE REFERENCE:
- frontend: Point d'entrée. Dépend de: productcatalog, cart, shipping, checkout.
- checkoutservice: Critique. Dépend de: payment, shipping, email, cart.
- cartservice: Gestion panier (Redis).
- shippingservice: Calcul logistique.
"""
 
SYSTEM_PROMPT = (
    "Rôle: Expert SRE Senior (Google Online Boutique).\n"
    "Objectif: Analyser les anomalies de monitoring (Value vs Threshold).\n"
    "Contrainte: Utilise UNIQUEMENT les balises [[TITRE]], [[DESCRIPTION]], [[RECOMMANDATIONS]].\n"
    "Rigueur: Identifie la root cause et l'impact sur les services dépendants."
)

class AIService:
    @staticmethod
    def _extract_section(text: str, tag: str) -> str:
        """Extrait le contenu entre des balises spécifiques [[TAG]]...[[/TAG]]."""
        pattern = f"\\[\\[{tag}\\]\\]\\s*(?::)?\\s*(.*?)(?=\\s*\\[\\[|$)"
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return f"Section {tag} non générée."

    @staticmethod
    async def generate_structured_analysis(data: list):
        client = ollama_lib.Client(host='http://localhost:11434')
        MODEL_NAME = "gemma3:4b"

        # --- PROMPT AVEC CONTRAINTES DE FORMATAGE ---
        prompt = f"""
        {TOPOLOGY}
        LOGS À ANALYSER: {data[:10]}
       
        Rédige un rapport technique court :
        - TITRE: Synthèse de l'incident.
        - DESCRIPTION: Pourquoi (seuil dépassé) et Qui (service impacté).
        - RECOMMANDATIONS: Actions techniques (kubectl, logs, etc).
 
        Génère le rapport avec les balises [[TITRE]], [[DESCRIPTION]], [[RECOMMANDATIONS]].

        Limite-toi à 200 mots par section.
        """

        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] analyse...")
            
            response = client.chat(
                model=MODEL_NAME,
                messages=[
                    {'role': 'system', 'content': SYSTEM_PROMPT},
                    {'role': 'user', 'content': prompt}
                ],
                options={"temperature": 0.2}
            )
            
            raw_text = response['message']['content']
            
            # --- PARSING DES VARIABLES ---
            analysis = {
                "titre": AIService._extract_section(raw_text, "TITRE"),
                "description": AIService._extract_section(raw_text, "DESCRIPTION"),
                "recommandations": AIService._extract_section(raw_text, "RECOMMANDATIONS"),
                "raw_output": raw_text #variable debeug
            }
            print(f"[{datetime.now().strftime('%H:%M:%S')}] fin analyse...")
            
            return analysis

        except Exception as e:
            print(f" Erreur AIService: {str(e)}")
            return None
    async def stream_structured_analysis(data: list):
        """Générateur envoyant les chunks de Gemma 3 au fur et à mesure."""
        client = Client(host='http://localhost:11434')
        MODEL_NAME = "gemma3:4b"
        print(f"[{datetime.now().strftime('%H:%M:%S')}] analyse...")

        prompt = f"""
        Analyse SRE pour Google Online Boutique. Logs : {data[:10]}
        Tu DOIS répondre impérativement en respectant ce format de balises :
        [[TITRE]] ... [[/TITRE]]
        [[DESCRIPTION]] ... [[/DESCRIPTION]]
        [[RECOMMANDATIONS]] ... [[/RECOMMANDATIONS]]
        """

        try:
            # On active le mode stream=True
            stream = client.chat(
                model=MODEL_NAME,
                messages=[
                    {'role': 'system', 'content': SYSTEM_PROMPT},
                    {'role': 'user', 'content': prompt}
                ],
                stream=True,
                options={"temperature": 0.2}
            )
            print(f"[{datetime.now().strftime('%H:%M:%S')}] apress stream...")

            for chunk in stream:
                token = chunk['message']['content']
                if token:
                    # On yield chaque mot/caractère immédiatement
                    yield token
            print(f"[{datetime.now().strftime('%H:%M:%S')}] fin chunck...")
        except Exception as e:
            yield f"Error: {str(e)}"