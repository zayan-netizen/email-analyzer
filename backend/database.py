import sqlite3

DATABASE_NAME = "email_analyzer.db"

def create_connection():

	conn = sqlite3.connect(DATABASE_NAME)

	return conn

def create_table():

	conn = create_connection()

	try:
		cursor = conn.cursor()

		cursor.execute("""
			CREATE TABLE IF NOT EXISTS reports (

				id INTEGER PRIMARY KEY AUTOINCREMENT,

				sender TEXT,

				subject TEXT,

				risk_score INTEGER,

				classification TEXT,

				analysed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)
				""")

		conn.commit()

	except sqlite3.Error as e:
		logger.error(f"Failed to create table: {e}")
	finally:
		conn.close()

def save_report(sender, subject, risk_score, classification):

	conn = create_connection()

	try:
		with conn:
			cursor = conn.cursor()

			cursor.execute("""
				INSERT INTO reports (
					sender,
					subject,
					risk_score,
					classification
				)
				VALUES(?, ?, ?, ?)
				""", (
					sender,
					subject,
					risk_score,
					classification
				))

			return cursor.lastrowid

	except sqlite3.Error as e:
		logger.error(f"Database error while saving report from {sender}: {e}")
		return None

	finally:
		conn.close()



	