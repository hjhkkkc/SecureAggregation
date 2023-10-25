import socket
import Config
import Client
import Server
import KeyAgreement
from DigitalSignature import DigitalSignature


def setup():
	key_distribution()


def key_distribution():
	keys = {}
	clients = [c[0] for c in Config.clients]
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	for u in clients:
		k = DigitalSignature.gen(Config.k)
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
