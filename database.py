import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

class MongoDB:
    client: AsyncIOMotorClient = None
    db = None

db_connection = MongoDB()
async def connect_to_mongo():
    uri = os.getenv("MONGODB_CONNECT_URI")
    try:
        # Configuration équivalente aux options Mongoose
        db_connection.client = AsyncIOMotorClient(
            uri,
            tlsInsecure=False # Sécurité TLS par défaut
        )
        # On cible la database
        db_connection.db = db_connection.client.PFE #mettre le nom de la bdd
        print(" Connected to MongoDB Database")
    except Exception as e:
        print(f" Could not connect to MongoDB: {e}")

async def close_mongo_connection():
    db_connection.client.close()
    print(" MongoDB connection closed")