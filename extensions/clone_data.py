from pymongo import MongoClient

# Configuration
ORIGINAL_DB = "threat_intel"
EXTENDED_DB = "threat_intel_ext"
COLLECTION = "raw_threats"
MONGO_URI = "mongodb://localhost:27017"

def clone_database():
    client = MongoClient(MONGO_URI)
    
    # Access original and new DB
    old_db = client[ORIGINAL_DB]
    new_db = client[EXTENDED_DB]
    
    try:
        # Get all documents from the original collection
        documents = list(old_db[COLLECTION].find())
        
        if not documents:
            print(f"No data found in {ORIGINAL_DB}.{COLLECTION} to clone.")
            return

        # Insert into the new database
        new_db[COLLECTION].insert_many(documents)
        
        print(f"Success! Cloned {len(documents)} IOCs to the new database: '{EXTENDED_DB}'")
        print("You can now safely use this database for all extensions.")
    except Exception as e:
        print(f"Error during cloning: {e}")

if __name__ == "__main__":
    clone_database()
