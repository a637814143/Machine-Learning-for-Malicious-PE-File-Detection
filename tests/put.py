import requests


files = {'file': open(r"C:\Users\86133\PycharmProjects\machine\data\raw\malware\VirusShare_ef83abda17af0db48b2dd1cd2b89a713.exe", 'rb')}  # 上传的 .exe 文件路径
r = requests.post('http://192.168.166.129:5000/upload', files=files, timeout=600)
print(r.json())