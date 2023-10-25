import math
import Math
import Random
import hashlib

class DigitalSignature:
	def gen(k):
		if k != 1024:
			return None
		
		p = Random.prime_number(k >> 1)
		q = Random.prime_number(k >> 1)
		n = p * q
		# print(p)
		# print(q)
		phi_n = (p - 1) * (q - 1)
		e = Random.randint(phi_n)
		while math.gcd(e, phi_n) != 1:
			e = Random.randint(phi_n)
		d = Math.exgcd(e, phi_n)

		sk = (n, p, q, e)
		pk = (n, d)
		return [sk, pk]

	def sig(sk, m):
		n, p, q, e = sk
		h = int(hashlib.sha256(m.encode()).hexdigest(), base=16) 
		sigma = Math.mod_exp(h, e, n)
		return sigma
		
	def ver(pk, m, sigma):
		n, d = pk
		h = int(hashlib.sha256(m.encode()).hexdigest(), base=16)
		h1 = Math.mod_exp(sigma, d, n)
		return h == h1