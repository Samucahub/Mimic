import asyncio
import sys
from core.controller import MIMICController

async def main_simple():
    controller = MIMICController("config/honeypot.yaml")
    try:
        await controller.start_all_services()
        print("\n[OK] Honeypot running -- Ctrl+C to stop\n")
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C received")
    finally:
        print("[*] Shutting down MIMIC...")
        await controller.stop()
        print("[OK] Shutdown complete")

def main():
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main_simple())
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[+] Program ended")

if __name__ == "__main__":
    main()