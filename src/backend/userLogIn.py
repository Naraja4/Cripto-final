from database.Database import Database
from Crypto.Hash import SHA256

class UserLogIn:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.db = Database()
    
    def login(self):

        data = self.lookupUsername()

        if data:
            salt = data[0][2]
            hash = data[0][3]

            if self.__hash_password(self.password, salt) == hash:
                return True

        return False
    
    def lookupUsername(self):
        return self.db.query(f"SELECT * FROM users WHERE username = '{self.username}'")
    
        #Esto returnea la salt y el hash de la password

    def __hash_password(self, password: str, salt: str) -> str:
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        sha256 = SHA256.new()
        sha256.update(salt_bytes + password_bytes)
        hashed_password = sha256.hexdigest()

        return hashed_password
    