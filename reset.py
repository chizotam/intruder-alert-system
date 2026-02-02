# reset_system.py
from db import cursor, db

def reset_system():
    # Delete all credentials
    cursor.execute("DELETE FROM credentials")

    # Clear intruder logs (this also resets the SERIAL sequences)
    cursor.execute("TRUNCATE TABLE intruder_logs RESTART IDENTITY")

    # Reset credentials sequence manually (PostgreSQL)
    cursor.execute("ALTER SEQUENCE credentials_id_seq RESTART WITH 1")

    # Commit changes
    db.commit()

    print("System reset complete. Database is now empty.")

if __name__ == "__main__":
    reset_system()
