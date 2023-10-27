

def mod_exp(b, e, m):
	# 计算b^e mod m 的结果，用于密钥协商
	A = 1
	S = b 
	e1 = e

	while e1 != 0:
		if e1 & 1:
			A = (A * S) % m
		e1 >>= 1
		S = (S * S) % m

	return A


def exgcd(a, n):
	# 通过扩展欧几里得算法来计算a在模n下的模逆元
	x1, x2, x3 = 1, 0, n
	y1, y2, y3 = 0, 1, a 

	while y3 != 0 and y3 != 1: 
		q = x3 // y3 
		t1, t2, t3 = x1 - q * y1, x2 - q * y2, x3 - q * y3 
		x1, x2, x3 = y1, y2, y3
		y1, y2, y3 = t1, t2, t3
	
	if y3 == 0:
		return None
	
	y2 %= n
	if y2 < 0:
		y2 += n
		
	return y2 
