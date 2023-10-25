import Math
import Random
import Config

class KeyAgreement:
	k = 1024
	p = Config.KA1024_p
	g = Config.KA1024_g
	q = Config.KA1024_q	
	
	def gen(pp = None):
		if pp != None:
			if pp[0] != 1024:
				return None
			KeyAgreement.k, KeyAgreement.p, KeyAgreement.g, KeyAgreement.q = pp
		
		# print(pp)
		sk = Random.randint(KeyAgreement.q)
		pk = Math.mod_exp(KeyAgreement.g, sk, KeyAgreement.p)
		return (sk, pk)

	def agree(A_sk, B_pk):
		return Math.mod_exp(B_pk, A_sk, KeyAgreement.p)
