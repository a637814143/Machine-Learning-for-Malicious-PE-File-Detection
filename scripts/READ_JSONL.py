import json

def read_jsonl(path, num_samples=5):
    """
    读取 JSONL 文件，并打印前 num_samples 条数据
    """
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= num_samples:
                break
            data = json.loads(line.strip())
            print(f"--- 样本 {i+1} ---")
            for key, value in data.items():
                if isinstance(value, dict):
                    print(f"{key}: dict ({len(value)} keys)")
                elif isinstance(value, list):
                    print(f"{key}: list ({len(value)} elements)")
                else:
                    print(f"{key}: {value}")
            print()

if __name__ == "__main__":
    # 修改为你的 EMBER 数据路径
    path = r"C:\ember_dataset_2018_2\train_features_0.jsonl"
    read_jsonl(path, num_samples=3)
