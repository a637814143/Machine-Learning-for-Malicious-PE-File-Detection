import re
import requests

URL = "http://challenge.bluesharkinfo.com:20871/encrypt"

def fetch_cipher(a: int, b: int, c: int, text: str) -> tuple[str, str]:
      data = {"a": str(a), "b": str(b), "c": str(c), "text": text}
      resp = requests.post(URL, data=data)
      resp.raise_for_status()
      fields = re.findall(r'hex-output">(.*?)</div>', resp.text, flags=re.S)
      if len(fields) < 2:
          raise RuntimeError("unexpected response:\n" + resp.text[:400])
      # 第一个 hex-output 是明文字节映射，第二个是 flag
      cipher = " ".join(fields[0].split())
      flag_hex = " ".join(fields[1].split())
      return cipher, flag_hex

def decode_flag(flag_hex: str) -> str:
      # 当 a=b=1, c=256 时，黑盒做的是每个字节加 1；因此减 1 还原
      raw = bytes(((int(byte, 16) - 1) % 256) for byte in flag_hex.split())
      return raw.decode("utf-8", errors="replace")

if __name__ == "__main__":
      _, flag_hex = fetch_cipher(a=1, b=1, c=256, text="hi")
      print("flag hex:", flag_hex)
      print("flag:", decode_flag(flag_hex))
