import subprocess
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

LOG_FILE = "logs/firewall_blocks.log"

def get_blocked_ips():
    if not os.path.exists(LOG_FILE):
        logger.info("No block log found")
        return []
    ips = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(" | ")
            if len(parts) == 3 and parts[1] == "BLOCKED":
                ips.append(parts[2])
    return ips

def unblock_ip(ip):
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        logger.info(f"Unblocked IP: {ip}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to unblock {ip}: {e}")
        return False

def rollback_all():
    ips = get_blocked_ips()
    if not ips:
        logger.info("No IPs to rollback")
        return
    logger.info(f"Rolling back {len(ips)} blocked IPs...")
    for ip in ips:
        unblock_ip(ip)
    # Clear log after rollback
    open(LOG_FILE, "w").close()
    logger.info("Rollback complete. Log cleared.")

if __name__ == "__main__":
    rollback_all()
