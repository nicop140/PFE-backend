import ollama
from fpdf import FPDF
import io
from datetime import datetime
from database import db_connection

class AIService:
    @staticmethod
    async def generate_audit_report(audit_id: str, data: list):
        """
        Génère un rapport via Ollama, crée un PDF et met à jour MongoDB.
        """
        # 1. Préparation du prompt
        # On résume les données pour ne pas dépasser la fenêtre de contexte
        degradations_summary = "\n".join([str(row) for row in data[:20]]) 
        
        prompt = f"""
        Tu es un expert en audit d'infrastructure. 
        Voici une liste de dégradations relevées sur le terrain :
        {degradations_summary}
        
        Rédige un rapport d'audit professionnel structuré :
        1. Résumé exécutif
        2. Analyse des risques
        3. Recommandations prioritaires.
        Sois précis et technique.
        """

        try:
            # 2. Appel à Ollama (Modèle conseillé : llama3 ou mistral)
            response = ollama.chat(model='llama3', messages=[
                {'role': 'user', 'content': prompt},
            ])
            report_text = response['message']['content']

            # 3. Génération du PDF en mémoire
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, txt=f"Rapport d'Audit - ID: {audit_id}", ln=True, align='C')
            pdf.ln(10)
            pdf.multi_cell(0, 10, txt=report_text)
            
            pdf_output = pdf.output(dest='S') # Sortie en bytes string

            # 4. Stockage dans MongoDB
            # On met à jour l'audit existant avec le contenu du rapport et le PDF
            await db_connection.db.PFE.update_one(
                {"_id": audit_id},
                {
                    "$set": {
                        "status": "COMPLETED",
                        "report_text": report_text,
                        "pdf_content": pdf_output, # Stocké en Binary
                        "completed_at": datetime.utcnow()
                    }
                }
            )
            print(f"✅ Rapport généré pour l'audit {audit_id}")

        except Exception as e:
            await db_connection.db.PFE.update_one(
                {"_id": audit_id},
                {"$set": {"status": "FAILED", "error": str(e)}}
            )
            print(f"❌ Erreur AI: {e}")