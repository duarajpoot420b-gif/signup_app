import sqlite3

conn = sqlite3.connect("database.db")
c = conn.cursor()
c.execute("UPDATE users SET role='admin' WHERE userid = ?", ("duarajpoot",))
conn.commit()
conn.close()
print("User promoted to admin.")
