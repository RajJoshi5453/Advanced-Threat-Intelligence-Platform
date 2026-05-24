import asyncio
import aiohttp
import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv("config/.env")

OTX_API_KEY = os.getenv("OTX_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]
collection = db["raw_threats"]

OTX_URL = "https://otx.alienvault.com/api/v1/indicators/export"

async def fetch_otx(session):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"type": "IPv4", "limit": 50}
    print("[*] Async fetching OTX...")
    async with session.get(OTX_URL, headers=headers, params=params) as resp:
        data = await resp.json()
        return data.get("results", [])

async def save_ioc(doc):
    existing = await collection.find_one({"indicator": doc["indicator"], "source": "OTX"})
    if not existing:
        await collection.insert_one(doc)
        return True
    return False

async def run():
    async with aiohttp.ClientSession() as session:
        results = await fetch_otx(session)
        print(f"[+] Fetched {len(results)} indicators")

        tasks = []
        for item in results:
            indicator = item.get("indicator")
            if not indicator:
                continue
            doc = {
                "indicator": indicator,
                "type": "IPv4",
                "source": "OTX",
                "pulse_count": item.get("pulse_info", {}).get("count", 0),
                "fetched_at": datetime.now(timezone.utc)
            }
            tasks.append(save_ioc(doc))

        saved_results = await asyncio.gather(*tasks)
        print(f"[+] Saved {sum(saved_results)} new IOCs asynchronously")

if __name__ == "__main__":
    asyncio.run(run())
