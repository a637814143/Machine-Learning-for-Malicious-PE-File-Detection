# scripts/split_jsonl.py
import os

def split_jsonl(input_path, output_path, max_mb=2):
    """
    从一个巨大的 jsonl 文件中截取前 max_mb MB，保存到 output_path。
    """
    max_bytes = max_mb * 1024 * 1024  # 转换成字节
    written = 0

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        for line in fin:
            line_size = len(line)
            if written + line_size > max_bytes:
                break
            fout.write(line)
            written += line_size

    print(f"已保存 {written/1024/1024:.2f} MB 到 {output_path}")

if __name__ == "__main__":
    # 修改这里为你本地的路径
    input_file = r"C:\ember_dataset_2018_2\train_features_0.jsonl"
    output_file = r"C:\ember_dataset_2018_2\train_features_0_2mb.jsonl"

    split_jsonl(input_file, output_file, max_mb=2)
