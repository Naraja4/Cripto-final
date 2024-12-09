from getPrivateKey import getPrivateKey
from getPublicKey import getPublicKey
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes




print("Test getPrivateKey")
private_key_path = "cripto_certs/Ivan/Ivankey.pem"
password = "1234"
getPrivateKey = getPrivateKey()
private_key = getPrivateKey.getPrivateKeyFromFile(private_key_path, password)
print(private_key)

print("Test getPublicKey")
certificate_path = "cripto_certs/Ivan/Ivancert.pem"
getPublicKey = getPublicKey()
public_key = getPublicKey.getPublicKeyFromCertificate(certificate_path)
print(public_key)
