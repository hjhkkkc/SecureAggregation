import socket
import Config
import Client
import Server
import KeyAgreement
from DigitalSignature import DigitalSignature
from gmssl import *


def setup():
	key_distribution()


# def key_distribution():
# 	keys = {}
# 	clients = [c[0] for c in Config.clients]
# 	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# 	for u in clients:
		# k = DigitalSignature.gen(Config.k)
# 		keys[u] = k

# 	for i in range(len(clients)):
# 		k = {}
# 		for j in range(len(clients)):
# 			if i == j:
# 				k[clients[j]] = keys[clients[j]]
# 			else:
# 				k[clients[j]] = keys[clients[j]][1]
# 		s.sendto(str(k).encode(), Config.clients[i][1])		
# 	s.close()

# 采用SM2国密算法的分发签名与验证密钥
def key_distribution():
	keys = {}
	clients = [c[0] for c in Config.clients]
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	for u in clients:
		# 原本的生成密钥
		# k = DigitalSignature.gen(Config.k)
		
		# 采用SM2国密算法的生成密钥,并且导出密钥，
		# 导出格式为clientID_sm2.pem与clientID_sm2pub.pem
		sm2 = Sm2Key()
		sm2.generate_key()
		tmp_pri = sm2.export_encrypted_private_key_info_pem(str(u)+'_sm2.pem', 'password')
		tmp_pub = sm2.export_public_key_info_pem(str(u)+'_sm2pub.pem')
		k = (tmp_pri, tmp_pub)
		keys[u] = k

	for i in range(len(clients)):
		k = {}
		for j in range(len(clients)):
			if i == j:
				k[clients[j]] = keys[clients[j]]
			else:
				k[clients[j]] = keys[clients[j]][1]
		s.sendto(str(k).encode(), Config.clients[i][1])		
	s.close()
