import requests


files = {'file': open(r"C:\Users\86133\Downloads\moon_client_vmprotect.exe", 'rb')}  # 上传的 .exe 文件路径
r = requests.post('http://192.168.166.128:5000/upload', files=files, timeout=600)
print(r.json())