import socket
import Config
import Random
from AE import AE
from Vector import Vector
from KeyAgreement import KeyAgreement
from SecretSharing import SecretSharing
from DigitalSignature import DigitalSignature

class Client:
	def __init__(self, ID, addr):
		# self.running = False
		self.ID = ID
		self.addr = addr
		self.R = Config.R
		self.server_addr = Config.server
		self.AE_key_bytes = Config.AE_key_length >> 3
		self.RECIEVE_BUFFER = Config.client_recieve_buffer 

	def abort(self):
		if(getattr(self.s, '_closed') == False):
			self.s.close()
		self.log("abort")

	def log(self, message):
		print("client " + str(self.ID) +" : ", message)

	def send(self, message, addr = None):
		if(getattr(self.s, '_closed') == True):
			return None

		if addr == None:
			self.s.sendto(message.encode(), self.server_addr)
		else:
			self.s.sendto(message.encode(), addr)

	def receive(self):
		self.s.settimeout(None)
		data, addr = self.s.recvfrom(self.RECIEVE_BUFFER)
		return eval(data.decode())

	def receive2(self):
		data = []
		addrs = []
		self.s.settimeout(None)
		flag = True
		while flag:
			try:
				d, a = self.s.recvfrom(self.RECIEVE_BUFFER)
				# self.log(d.decode())
				data.append(eval(d.decode()))
				addrs.append(a)
				self.s.settimeout(Config.client_timeout)
				flag = True
			except socket.timeout:
				flag = False
			except Exception as e:
				flag = False
				self.log("error : " + str(e))
		# addrs = list(set(addrs))
		return data, addrs

	def check(self, U):
		# self.log(len(U) < Config.t)
		if (len(U) < Config.t):
			self.log("error : user less than " + str(Config.t))
			self.abort()

	def set_x_u(self, v):
		self.x_u = Vector(v.get_values())
	
	def get_x_u(self):
		return Vector(self.x_u.get_values())

	def recieve_z(self):
		if(getattr(self.s, '_closed') == True):
			return None

		result = self.recieve()
		self.log("the result of secure aggregation : " + result)

	def setup(self):
    # 设置客户端的初始化方法
		self.log("setup --- start")  # 记录日志，表示初始化开始

		# 创建一个 UDP 套接字并绑定到指定地址
		self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.s.bind(self.addr)

		# 接收数据，由于这个数据给出du_sk、du_pk，由setup中的Key_Distribution完成
		data = self.receive()

		# 从接收到的数据中提取出每个客户端的du_sk(Signing Key)、dv_pk(Verification Key)
		self.d_sk, self.d_pk = data[self.ID]

		# 
		self.U_d_pk = data
		self.U_d_pk[self.ID] = self.d_pk

		# 记录日志，表示初始化完成
		self.log("setup --- finish")


	def run(self):
		self.AdvertiseKeys()
		self.ShareKeys()
		self.MaskedInputCollection()
		self.ConsistencyCheck()
		self.Unmasking()
	



	
	def AdvertiseKeys(self):
		# 广播密钥的方法

		self.log("AdvertiseKeys --- start")  # 记录日志，表示广播密钥操作开始

		# 生成c_sk、c_pk，以及s_sk、s_pk
		self.c_sk, self.c_pk = KeyAgreement.gen(Config.pp1024)
		self.s_sk, self.s_pk = KeyAgreement.gen(Config.pp1024)

		# 使用self.d_sk对self.c_pk和self.s_pk进行数字签名，并生成签名值（sigma）
		sigma = DigitalSignature.sig(self.d_sk, str(self.c_pk) + str(self.s_pk))

		# 构建一个消息（m），包括当前用户的标识（self.ID）、客户端公钥（self.c_pk）、服务器公钥（self.s_pk）和签名值（sigma）
		m = (self.ID, self.c_pk, self.s_pk, sigma)

		# 使用套接字（self.send）将消息（m）发送给Server
		self.send(str(m))

		self.log("AdvertiseKeys --- finish")  # 记录日志，表示广播密钥操作完成


	def ShareKeys(self):
		self.log("ShareKeys --- start")  # 记录日志，表示进入 ShareKeys 函数

		data = self.recieve()  # 接收数据
		self.check(data)  # 判断是否有≥t个用户

		self.U1 = []  # 用于存储用户标识
		self.U_c_pk = {}
		self.U_s_pk = {}

		# 遍历接收到的数据
		for item in data:
			u, c_u_pk, s_u_pk, sigma_u = item

			# 使用数字签名验证数据的完整性和真实性
			res = DigitalSignature.ver(self.U_d_pk[u], str(c_u_pk) + str(s_u_pk), sigma_u)
			if not res:
				self.log("ShareKeys : verification fail !!!")  # 如果验证失败，记录错误信息并中止
				self.abort()
				return

			self.U1.append(u)  # 将用户标识添加到 U1 列表中
			self.U_c_pk[u] = c_u_pk  # 存储c_u_pk
			self.U_s_pk[u] = s_u_pk  # 存储s_u_pk

		self.b_u = Random.randint(Config.Ru)  # 生成随机数 b_u
		U_s_uv = SecretSharing.share(self.s_sk, Config.t, len(self.U1))  # 使用秘密分享生成 U_s_uv
		U_b_uv = SecretSharing.share(self.b_u, Config.t, len(self.U1))  # 使用秘密分享生成 U_b_uv

		u = self.ID
		for i in range(len(self.U1)):
			v = self.U1[i]

			if v == u:
				continue

			k = KeyAgreement.agree(self.c_sk, self.U_c_pk[v])  # 使用密钥协商生成共享密钥 k
			k = str(k)[:self.AE_key_bytes].encode()  # 转换共享密钥 k 为字节串

			m = (u, v, U_s_uv[i], U_b_uv[i])  # 构建消息 m，包括 u, v, U_s_uv 和 U_b_uv
			e_uv = AE.enc(k, str(m))  # 使用加密算法 AE 对消息 m 进行加密
			m = (u, v, e_uv)  # 更新消息 m，只包括 u, v, e_uv
			self.send(str(m))  # 发送消息

		self.log("ShareKeys --- finish")  # 记录日志，表示 ShareKeys 函数结束


	def MaskedInputCollection(self):
		self.log("MaskedInputCollection --- start")  # 记录日志，表示掩蔽输入数据收集开始

		data, addrs = self.receive2()  # 接收数据和对应的地址

		self.check(data)  # 调用检查方法检查数据
		self.U2 = []  # 初始化 U2 列表，用于存储用户标识
		self.U_e_uv = {}  # 初始化 U_e_uv 字典
		sum_puv = Vector(Config.m)  # 创建 Vector 对象用于存储累计的 p_uv 值
		u = self.ID  # 获取当前客户端的标识
		self.U2.append(u)  # 将当前客户端标识添加到 U2 列表中

		for item in data:
			v, e_uv = item  # 从数据项中获取用户标识和 e_uv 数据
			self.U_e_uv[v] = e_uv  # 将用户标识与 e_uv 映射关系存储在 U_e_uv 字典中
			self.U2.append(v)  # 将用户标识添加到 U2 列表中

			if u == v:  # 如果当前用户与数据项中的用户标识相同，则跳过后续操作
				continue

			s_uv = KeyAgreement.agree(self.s_sk, self.U_s_pk[v])  # 计算密钥协商结果 s_uv
			p_uv = Vector(Random.PRG(s_uv, Config.Ru, Config.m))  # 使用随机数生成器生成 p_uv 向量
			if u < v:  # 如果当前用户标识小于数据项中的用户标识
				p_uv = p_uv * (-1)  # 将 p_uv 向量取反

			sum_puv = sum_puv + p_uv  # 将 p_uv 累加到 sum_puv 向量中

		p_u = Vector(Random.PRG(self.b_u, Config.Ru, Config.m))  # 使用随机数生成器生成 p_u 向量
		y_u = (self.x_u + p_u + sum_puv) % self.R  # 计算 y_u 值

		m = (u, y_u)  # 构建消息 m，包含用户标识和 y_u 数据
		self.send(str(m))  # 发送消息 m 到其他客户端
		self.log("MaskedInputCollection --- finish")  # 记录日志，表示掩蔽输入数据收集完成


	def ConsistencyCheck(self):
		self.log("ConsistencyCheck --- start")
		data = self.recieve()
		self.check(data)
		# self.U3 = data 			# a dict
		self.U3 = data.keys()
		# self.log(str(self.U3))
		sigma = DigitalSignature.sig(self.d_sk, str(self.U3))
		m = (self.ID, sigma)
		self.send(str(m))
		self.log("ConsistencyCheck --- finish")

	def Unmasking(self):
		self.log("Unmasking --- start")
		data = self.recieve()
		for item in data:
			# self.log(item)
			v, sigma = item
			res = DigitalSignature.ver(self.U_d_pk[v], str(self.U3), sigma)
			if not res:
				self.log("Unmasking : verification fail !!!")
				self.abort()
				return
		U_s_uv = {}
		U_b_uv = {}
		u = self.ID
		for v in self.U2:
			if v == u:
				continue
			k = KeyAgreement.agree(self.c_sk, self.U_c_pk[v])
			k = str(k)[:self.AE_key_bytes].encode()
			# self.log(type(AE.dec(k, self.U_e_uv[v])))
			# self.log(len(AE.dec(k, self.U_e_uv[v])))
			v_prime, u_prime, s_uv, b_uv = eval(AE.dec(k, self.U_e_uv[v]))
			if u_prime != u and v_prime != v:
				self.log("Unmasking : unmatched user ID !!!")
				self.abort()
				return
			U_s_uv[v] = s_uv
			U_b_uv[v] = b_uv
		# self.log(str(U_s_uv))
		# self.log(str(U_b_uv))
		# self.log(str(set(self.U2)))
		# self.log(str(set(self.U3)))
		# self.log(str(set(self.U2) - set(self.U3)))
		for v in set(self.U2) - set(self.U3):
			if v == u:
				continue
			m = (u, v, "s_uv", U_s_uv[v])
			self.log("s_uv")
			self.send(str(m))
		for v in self.U3:
			if v == u: # promble
				continue
			# self.log("b_uv")
			m = (u, v, "b_uv", U_b_uv[v]) # !!! note !!! : u, v
			self.send(str(m))
		self.log("Unmasking --- finish")



