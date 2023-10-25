import socket
import Config
import Random
from Vector import Vector
from KeyAgreement import KeyAgreement
from SecretSharing import SecretSharing

class Server:
	def __init__(self, addr):
		self.addr = addr
		self.R = Config.R
		self.RECIEVE_BUFFER = Config.server_recieve_buffer

	def abort(self):
		if(getattr(self.s, '_closed') == False):
			self.s.close()
		self.log("abort")

	def log(self, message):
		print("server : ", message)

	def send(self, message, addrs):
		# 发送消息的方法
		# 检查套接字是否已关闭，如果已关闭则不执行任何操作
		if getattr(self.s, '_closed') == True:
			return None

		# 遍历要发送消息的目标地址列表
		for addr in addrs:
			# 使用套接字（self.s）向指定地址（addr）发送消息
			self.s.sendto(message.encode(), addr)

	def receive(self):
		# 创建一个空列表 data 用于存储接收到的数据
		data = []
		
		# 创建一个空列表 addrs 用于存储发送数据的地址信息
		addrs = []
		
		# 设置套接字的超时时间为 None，以便无限等待数据到达
		self.s.settimeout(None)
		
		# 创建一个标志变量 flag，用于控制循环是否继续执行
		flag = True 
		
		# 进入循环，等待接收数据
		while flag:
			try:
				# 使用套接字 (self.s) 接收数据和发送数据的地址 (d, a)
				d, a = self.s.recvfrom(self.RECIEVE_BUFFER)
				
				# 将接收到的数据解码并将结果添加到 data 列表中
				data.append(eval(d.decode()))
				
				# 将发送数据的地址信息添加到 addrs 列表中
				addrs.append(a)
				
				# 设置套接字的超时时间为 Config.server_timeout，以便在下次接收数据时超时等待
				self.s.settimeout(Config.server_timeout)
				
				# 将标志变量 flag 设置为 True，表示可以继续循环接收数据
				flag = True
			except socket.timeout:
				# 如果发生超时，将标志变量 flag 设置为 False，结束循环
				flag = False
			except Exception as e:
				# 如果发生异常，将标志变量 flag 设置为 False，结束循环，并记录错误信息
				flag = False
				self.log("error : " + str(e))
		
		# 在接收完成后，返回接收到的数据列表 data 和发送数据的地址列表 addrs
		return data, addrs



	def check(self, U):
		if (len(set(U)) < Config.t):
			self.log("error : user less than " + str(Config.t))
			self.abort()
			return False
		return True

	def collect_users(self, data, addrs):
		# 收集接收到消息的发送者对应的ip地址信息
		U = {}
		for i in range(len(addrs)):
			U[data[i][0]] = addrs[i]
		return U

	def set_z(self, v):
		self.z = Vector(v.get_values())

	def get_z(self):
		return Vector(self.z.get_values())

	def setup(self):
    	# 设置服务器的初始化方法
		self.log("setup --- start")  # 记录日志，表示初始化开始

		# 创建一个 UDP 套接字并将其绑定到服务器指定的地址（self.addr）上
		self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.s.bind(self.addr)

		# 记录日志，表示初始化完成
		self.log("setup --- finish")  # 记录日志，表示初始化完成


	def run(self):
		self.AdvertiseKeys()
		self.ShareKeys()
		self.MaskedInputCollection()
		self.ConsistencyCheck()
		self.Unmasking()







	def AdvertiseKeys(self):
		# 广播密钥的方法

		self.log("AdvertiseKeys --- start")  # 记录日志，表示广播密钥操作开始

		# 接收Client发来的数据，获取数据和地址信息
		data, addrs = self.receive()
		
		# 检查接收到的地址信息，可能是用于验证来源的安全性检查
		self.check(addrs)

		# 初始化一个字典来存储其他用户的公钥信息
		self.U_s_pk = {}

		# 遍历接收到的数据，每个数据项包含了用户标识(u)、客户端公钥(c_u_pk)、服务器公钥(s_u_pk)和签名(sigma)
		for item in data:
			u, c_u_pk, s_u_pk, sigma = item

			# 将服务器公钥(s_u_pk)与用户标识(u)关联并存储在 U_s_pk 字典中，在Unmasking阶段用到。
			self.U_s_pk[u] = s_u_pk

		# 向指定地址（addrs）发送包含数据的消息
		self.send(str(data), addrs)

		self.log("AdvertiseKeys --- finish")  # 记录日志，表示广播密钥操作完成


	def ShareKeys(self):
		# 分享密钥的方法。
		# 从其他客户端接收加密后的密钥数据，解密并验证数据，然后将解密后的数据发送给其他客户端。
		self.log("ShareKeys --- 开始")
		data, addrs = self.receive()  # 接收数据和地址
		self.check(addrs)  # 验证地址的合法性
		self.U2 = self.collect_users(data, addrs)  # 获取用户对应的ip地址字典
		for item in data:
			u, v, e_uv = item
			m = (u, e_uv)
			addr = [self.U2[v]]
			self.send(str(m), addr)  # 发送数据
		self.log("ShareKeys --- 完成")


	def MaskedInputCollection(self):
		self.log("MaskedInputCollection --- start")  # 记录日志，表示掩蔽输入数据收集开始

		data, addrs = self.recieve()  # 接收数据和对应的地址

		self.check(addrs)  # 调用检查方法检查地址数据
		self.U3 = self.collect_users(data, addrs)  # 调用 collect_users 方法，收集用户数据和地址
		self.U_y = {}  # 初始化 U_y 字典，用于存储用户标识和 y_u 数据

		for item in data:
			u, y_u = item  # 从数据项中获取用户标识和 y_u 数据
			self.U_y[u] = Vector(y_u)  # 将用户标识与 y_u 数据映射存储在 U_y 字典中

		self.send(str(self.U3), addrs)  # 向其他客户端发送 U3 数据和地址
		self.log("MaskedInputCollection --- finish")  # 记录日志，表示掩蔽输入数据收集完成


	def ConsistencyCheck(self):
		self.log("ConsistencyCheck --- start")
		data, addrs = self.recieve()
		# self.log(str(data))
		self.check(addrs)
		self.U4 = self.collect_users(data, addrs)
		self.send(str(data), addrs)
		self.log("ConsistencyCheck --- finish")

	def Unmasking(self):
		self.log("Unmasking --- start")
		data, addrs = self.recieve()
		# self.log(str(data))
		# self.log(str(addrs))
		self.check(addrs)
		self.U5 = self.collect_users(data, addrs)
		U_s_uv = {}
		U_b_uv = {}
		for item in data:
			u, v, t, d = item 	# !!! note !!! : u, v
			if t == "s_uv":
				l = U_s_uv.get(v, [])
				l.append(d)
				U_s_uv[v] = l
			elif t == "b_uv":
				l = U_b_uv.get(v, [])
				l.append(d)
				U_b_uv[v] = l
		U_sum_puv = {}
		for u in self.U3:
			U_sum_puv[u] = Vector(Config.m)
		for u in set(self.U2) - set(self.U3):
			s_sk = SecretSharing.reconstruction(U_s_uv[u], Config.t)
			for v in self.U5:
				s_uv = KeyAgreement.agree(s_sk, self.U_s_pk[u])
				p_uv = Vector(Random.PRG(s_uv, Config.Ru, Config.m))
				if u < v:
					p_uv = p_uv * (-1)
				U_sum_puv[u] = U_sum_puv[u] + p_uv
		U_p_u = {}
		# self.log(U_b_uv)
		for u in self.U3:
			b_u = SecretSharing.reconstruction(U_b_uv[u], Config.t)
			# self.log("client {0} : b_u : {1}".format(u, b_u))
			U_p_u[u] = Vector(Random.PRG(b_u, Config.Ru, Config.m))
		# self.log("y_u : " + str(self.U_y))
		# self.log("p_u : " + str(p_u))
		# self.log("sum_puv : " + str(sum_puv))
		self.z = Vector(Config.m)
		for u in self.U3:
			# t = (self.U_y[u] - U_p_u[u] + U_sum_puv[u]) % self.R 
			# self.z = (self.z + t) % self.R
			self.z = (self.z + self.U_y[u] - U_p_u[u] + U_sum_puv[u]) % self.R 
		# self.log(str(self.z))
		# self.send(self.z, addrs)
		self.log("Unmasking --- finish")



