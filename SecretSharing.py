import Math
import Config
import random

class SecretSharing:
	k = 1024
	p = Config.SS1024_p

	def init(p):
		SecretSharing.p = p

	def share(s, t, u):
		# s：这是要进行秘密分享的原始秘密值，即需要被分割成份额的秘密数据。
		# t：这是生成多项式的阶数，也就是多项式中包含的项数。多项式的阶数决定了需要多少份额才能还原原始秘密值。
		# u：这是生成的份额的数量，即函数将生成多少个份额用于分发给不同的参与方。通常情况下，u 应该大于或等于 t，以确保有足够的份额用于还原秘密。
		# 初始化一个空列表来存储生成的份额
		shares = []
		
		# 创建一个多项式，以 s 作为首项系数
		poly = [s]
		
		# 生成多项式的剩余系数，共 t-1 个
		for i in range(t - 1):
			poly.append(random.randint(1, SecretSharing.p - 1))

		i = 0
		while i < u:
			# 随机选择一个 x 值，确保不重复
			x = random.randint(1, SecretSharing.p - 1)
			y = 0

			if x in [a[0] for a in shares]:
				continue

			# 使用多项式来计算 y 的值
			for j in range(t - 1, 0, -1):
				y += poly[j]
				y *= x
				y %= SecretSharing.p

			y += poly[0]
			y %= SecretSharing.p
			
			# 将 x 和计算得到的 y 作为一个份额，并添加到 shares 列表中
			shares.append([x, y])
			i += 1

		return shares


	def reconstruction(shares, t):
		# if t < len(shares):
		# 	return None
		if len(shares) < t:
			return None

		# print(shares)

		A = []

		for i in range(t):
			row = [1]
			tmp = 1
			for j in range(t - 1):
				tmp *= shares[i][0]
				tmp %= SecretSharing.p
				row.append(tmp)
			row.append(shares[i][1])
			A.append(row)	
		
		# print(A)

		for i in range(t - 1):	
			tmp1 = A[i][t - 1 - i]
			for j in range(i + 1, t):
				tmp2 = A[j][t - 1 - i]
				# print("tmp1 : {}, tmp2 : {}".format(tmp1, tmp2))
				for k in range(t - 1 - i, -1, -1):
					A[j][k] = (A[j][k] * tmp1 - A[i][k] * tmp2) % SecretSharing.p
				A[j][t] = (A[j][t] * tmp1 - A[i][t] * tmp2) % SecretSharing.p

			# print("i : ", i, A)

		return (A[t - 1][t] * Math.exgcd(A[t - 1][0], SecretSharing.p)) % SecretSharing.p
		# return (A[t - 1][t] / A[t - 1][0]) % self.p
	
	