import time
import Setup
import Config
import Random
import multiprocessing                                                       
from Vector import Vector
from Client import Client
from Server import Server

def task_client(ID, ip, port, x_u):
    
    # 以下两行完成了把特定的信息初始化到我们要操作的client
    addr = (ip, port)
    client = Client(ID, addr)
    
    # 这个x_u是什么向量，等下看看在哪里使用再说。
    x_u[ID] = Vector(Random.PRG(None, Config.Ru, Config.m))
    client.set_x_u(x_u[ID])
    client.setup()
    client.run()
    client.abort()

def task_server(ip, port, z):
    addr = (ip, port)
    # 下面这行初始化Sever的基本信息，如接收缓冲区大小，地址等。
    server = Server(addr)
    server.setup()
    server.run()
    server.abort()
    z.append(server.get_z())





def main():
    # shared variables
    manager = multiprocessing.Manager()
    x_u = manager.dict()
    z = manager.list()

    # setup
    process_clients = []
    for i in range(len(Config.clients)):
        process_clients.append(multiprocessing.Process(target=task_client, args=(Config.clients[i][0], *Config.clients[i][1], x_u)))
        process_clients[-1].deamon = True
        # process_clients[-1].name = "client " + str(Config.clients[i][0])
    process_server = multiprocessing.Process(target=task_server, args=(*Config.server, z))
    process_server.deamon = True
    # process_server.name = "server"

    # start
    process_server.start()
    for i in range(len(Config.clients)):
        process_clients[i].start()
    time.sleep(1)
    # 以下步骤完成密钥分发。建立一个二维矩阵
    # if i==j，表示生成的密钥信息是用于当前客户端自己的密钥。
    # if i != j，表示生成的密钥信息是用于将密钥发送给其他客户端的部分，即公钥。
    Setup.setup()

    # finish
    for i in range(len(Config.clients)):
        process_clients[i].join()
    process_server.join()

    # result
    print("\n\n\n")
    print("=========================Test Result============================")
    z = z[0]
    x_sum = Vector(Config.m)
    for i in range(len(Config.clients)):
        u = Config.clients[i][0]
        print("client {0} :  x_u  : {1}".format(u, str(x_u[u])))
        x_sum = (x_sum + x_u[u]) % Config.R
    print("clients  : x_sum :", x_sum)
    print("server   :   z   :", z)
    print("secure aggregation : ", z == x_sum)



if __name__ == "__main__":
    main()
