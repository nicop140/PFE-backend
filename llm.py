import ollama as ollama_lib
import re
from datetime import datetime

class AIService:
    @staticmethod
    def _extract_section(text: str, tag: str) -> str:
        """Extrait le contenu entre des balises spécifiques [[TAG]]...[[/TAG]]."""
        pattern = f"\\[\\[{tag}\\]\\](.*?)\\[\\[/{tag}\\]\\]"
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        return match.group(1).strip() if match else f"Section {tag} non générée."

    @staticmethod
    async def generate_structured_analysis(data: list):
        client = ollama_lib.Client(host='http://localhost:11434')
        MODEL_NAME = "gemma3:4b"

        # --- PROMPT AVEC CONTRAINTES DE FORMATAGE ---
        prompt = f"""
        En tant qu'expert SRE pour 'Google Online Boutique', analyse ces logs :
        {data[:15]}

        Tu DOIS répondre impérativement en respectant ce format de balises :
        [[TITRE]] Un titre court et percutant de l'incident [[/TITRE]]
        [[DESCRIPTION]] Une analyse détaillée de la cause racine et des services impactés [[/DESCRIPTION]]
        [[RECOMMANDATIONS]] Liste des actions correctives à entreprendre [[/RECOMMANDATIONS]]
        """

        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] analyse...")
            
            response = client.chat(model=MODEL_NAME, messages=[
                {'role': 'system', 'content': 'Tu es un assistant technique qui répond uniquement via les balises demandées.'},
                {'role': 'user', 'content': prompt}
            ])
            
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