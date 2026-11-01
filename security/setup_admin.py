"""Initialize the first dashboard administrator interactively."""
import argparse, getpass
from shared.database import init_db
from .accounts import initialize_admin

def main():
    p=argparse.ArgumentParser(); p.add_argument("--db",required=True); p.add_argument("--username",required=True); a=p.parse_args()
    first=getpass.getpass("New administrator password (12+ characters): ")
    second=getpass.getpass("Confirm password: ")
    if first != second: raise SystemExit("Passwords do not match")
    conn=init_db(a.db)
    try: uid=initialize_admin(conn,a.username,first)
    finally: conn.close()
    print(f"Administrator initialized (user_id={uid}).")

if __name__ == "__main__": main()
