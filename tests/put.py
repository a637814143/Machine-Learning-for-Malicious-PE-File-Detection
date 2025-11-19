import numpy as np

p = r"C:\Users\86133\PycharmProjects\machine\data\processed\npy\2025.11.13_22.43.npz"

data = np.load(p)  # 加载 .npz 文件

print(data.files)  # 查看里面有哪些数组的键名

for k in data.files:
    print(k, data[k].shape)