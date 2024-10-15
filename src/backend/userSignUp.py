from database.Database import Database
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

class UserSignUp:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.db = Database()
    
    def signup(self):
        salt = get_random_bytes(32).hex()
        hashed_password = self.__hash_password(self.password, salt)
        self.db.query(f"INSERT INTO users (username, salt, hash) VALUES ('{self.username}', '{salt}', '{hashed_password}')")

    def __hash_password(self, password: str, salt: str) -> str:
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        sha256 = SHA256.new()
        sha256.update(salt_bytes + password_bytes)
        hashed_password = sha256.hexdigest()

        return hashed_password
    
    