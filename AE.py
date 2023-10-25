from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AE:
	KEYS = []
	
	def gen(bit):
		if bit != 128:
			return None
			
		return get_random_bytes(bit >> 3)
		
	def enc(key, message):
		cipher = AES.new(key, AES.MODE_EAX)
		ciphertext, tag = cipher.encrypt_and_digest(message.encode())
		return (cipher.nonce, tag, ciphertext)

	def dec(key, ciphertexts):
		nonce, tag, ciphertext = ciphertexts
		cipher = AES.new(key, AES.MODE_EAX, nonce)
		data = cipher.decrypt_and_verify(ciphertext, tag)
		return data.decode()

	def key_expension(key):
		pass

	def enc_block(key, plaintext):
		pass

	def dec_block(key, ciphertext):
		pass