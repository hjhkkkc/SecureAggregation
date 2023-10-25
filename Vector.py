class Vector:
	
	def __init__(self, values):
		if isinstance(values, int):
			self.n = values
			self.values = [0] * self.n
		elif isinstance(values, list):
			self.n = len(values)
			self.values = [v for v in values]
	
	def set_values(self, values):
		for i in range(len(values)):
			self.values[i] = values[i]

	def get_values(self):
		return [v for v in self.values]

	def __str__(self):
		return str(self.values)

	def __repr__(self):
		return str(self.values)

	def __add__(self, vector):
		tmp = Vector(self.n)
		for i in range(self.n):
			tmp.values[i] = self.values[i] + vector.values[i]
		return tmp

	def __sub__(self, vector):
		tmp = Vector(self.n)
		for i in range(self.n):
			tmp.values[i] = self.values[i] - vector.values[i]
		return tmp

	def __mul__(self, m):
		tmp = Vector(self.n)
		for i in range(self.n):
			tmp.values[i] = self.values[i] * m
		return tmp

	def __eq__(self, vector):
		if self.n != vector.n:
			return False
		for i in range(self.n):
			if self.values[i] != vector.values[i]:
				return False
		return True

	def __mod__(self, m):
		tmp = Vector(self.n)
		for i in range(self.n):
			tmp.values[i] = self.values[i] % m
		return tmp
	
