import ollama as ollama_lib
from ollama import Client
from fpdf import FPDF
import io
from bson.binary import Binary
from datetime import datetime
from database import db_connection

class AIService:
    @staticmethod
    def _clean_text(text: str) -> str:
        """Nettoie le texte pour éviter les erreurs d'encodage FPDF standard."""
        return text.replace("’", "'").replace("–", "-").replace("€", "EUR").encode('latin-1', 'ignore').decode('latin-1')

    @staticmethod
    async def generate_audit_report(audit_id: str, data: list):
        # Initialisation du client explicite
        print('debut')
        client = ollama_lib.Client(host='http://localhost:11434')
        MODEL_NAME = "gemma3:4b"

        # Préparation du prompt pour Google Online Boutique
        prompt = f"""
        En tant qu'expert SRE, analyse ces logs de la 'Google Online Boutique' :
        {data[:10]}
        
        Rédige un rapport technique court avec :
        1. Cause racine probable.
        2. Impact sur les microservices dépendants.
        """

        try:
            print('la', datetime.now().strftime("%H:%M:%S"))
            # 1. Génération par l'IA
            response = client.chat(model=MODEL_NAME, messages=[
                {'role': 'user', 'content': prompt}
            ])
            raw_report = response['message']['content']
            print(raw_report)
            # Nettoyage crucial pour le PDF
            safe_report = AIService._clean_text(raw_report)
            print(safe_report)
          # 2. Création du PDF
            print('debut')
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", 'B', 16)
            pdf.cell(0, 10, "Rapport d'Audit - PFE", ln=True, align='C')
            pdf.ln(10)
            
            pdf.set_font("Helvetica", size=11)
            pdf.multi_cell(0, 8, txt=safe_report)
            
            pdf_output = pdf.output(dest='S')
            pdf_binary_data = Binary(bytes(pdf_output))
            print('avant mise en bdd', datetime.now().strftime("%H:%M:%S"))
            # 3. Sauvegarde MongoDB
            await db_connection.db.PFE.update_one(
                {"_id": audit_id},
                {
                    "$set": {
                        "status": "COMPLETED",
                        "report_text": raw_report, # On garde le texte riche en DB
                        "pdf_binary": pdf_binary_data,   # On stocke le PDF nettoyé
                        "processed_at": datetime.utcnow()
                    }
                }
            )
            print(f" Audit {audit_id} généré.")

        except Exception as e:
            print(f" Erreur critique dans AIService: {str(e)}")
            await db_connection.db.PFE.update_one(
                {"_id": audit_id},
                {"$set": {"status": "FAILED", "error": str(e)}}
            )