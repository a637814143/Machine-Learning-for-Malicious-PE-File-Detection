# tcp_4444_server.py
import socket
import time

s = socket.socket()
s.bind(("127.0.0.1", 4444))
s.listen(1)
print("listening 127.0.0.1:4444 ...")
c, addr = s.accept()
time.sleep(10)
print("client:", addr)
data = c.recv(4096)
print("recv:", data[:200])
c.sendall(b"OK\n")  # 给demo的recv一个返回
c.close()
s.close()
print("done")
