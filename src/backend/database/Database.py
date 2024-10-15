import mysql.connector


class Database:
    def __init__(self):
        self.cnx = mysql.connector.connect(user='user', password='userpassword',
                              host='127.0.0.1:3306', database='testdb')
        
    def query(self, query):
        cursor = self.cnx.cursor()
        cursor.execute(query)
        return cursor.fetchall()

    def close(self):
        self.cnx.close()
