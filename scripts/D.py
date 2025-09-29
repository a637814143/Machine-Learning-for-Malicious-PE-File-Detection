#!/usr/bin/env python3
"""
Process-pool runner with per-file timeout + robust wait loop.
- 单文件超时（TIMEOUT_SECONDS）后跳过
- 最多扫描 MAX_TO_SCAN 个文件
- 在主进程统计恶意数量/均值/最大/最小，保存 CSV
"""

from __future__ import annotations
import sys
import os
from pathlib import Path
import time
from typing import List, Tuple, Optional
from concurrent.futures import ProcessPoolExecutor, TimeoutError, wait, FIRST_COMPLETED

# ----------------- 配置区（只需修改这几处） -----------------
# 可以是单个文件或目录
PATH_TO_SCAN = Path(r"C:\Users\86133\PycharmProjects\machine\data\raw\benign")
MODEL_PATH = Path(r"C:\Users\86133\PycharmProjects\machine\data\processed\models\model.txt")
THRESHOLD = 0.0385

# 最大进程数（不要太大，避免内存压力）
MAX_WORKERS = min(12, (os.cpu_count() or 8))
# 单文件超时（秒）
TIMEOUT_SECONDS = 200
# 本次最多处理的文件数
MAX_TO_SCAN = 1500
# -----------------------------------------------------------

# 将项目根加入 sys.path（以便子进程也能 import core.*）
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# 这些 import 主/子进程都需要
try:
    import lightgbm as lgb
except Exception as exc:
    raise ImportError("请先安装 lightgbm: pip install lightgbm") from exc

from core.feature_engineering import extract_features, vectorize_features

PE_SUFFIXES = {".exe", ".dll", ".sys", ".bin", ".scr", ".ocx"}

# 由子进程在 initializer 中设置
GLOBAL_BOOSTER = None  # type: ignore
GLOBAL_MODEL_PATH = None  # type: ignore


def _init_worker(model_path_str: str) -> None:
    """每个子进程启动时加载模型一次"""
    global GLOBAL_BOOSTER, GLOBAL_MODEL_PATH
    GLOBAL_MODEL_PATH = model_path_str
    try:
        GLOBAL_BOOSTER = lgb.Booster(model_file=model_path_str)
    except Exception as e:
        GLOBAL_BOOSTER = None
        print(f"[worker init] 无法加载模型 {model_path_str}: {e}", file=sys.stderr)


def _worker_predict(path_str: str, threshold: float) -> Tuple[str, Optional[float], Optional[str], Optional[str]]:
    """
    子进程运行：提取特征并预测
    返回: (文件 path, probability or None, verdict or None, error_msg or None)
    """
    global GLOBAL_BOOSTER, GLOBAL_MODEL_PATH
    try:
        if GLOBAL_BOOSTER is None:
            if GLOBAL_MODEL_PATH is None:
                raise RuntimeError("Worker 模型路径未设置")
            GLOBAL_BOOSTER = lgb.Booster(model_file=GLOBAL_MODEL_PATH)

        from numpy import asarray, float32  # 子进程内按需导入
        path = Path(path_str)
        features = extract_features(path)
        vector = vectorize_features(features)
        arr = asarray(vector, dtype=float32).reshape(1, -1)
        prob = float(GLOBAL_BOOSTER.predict(arr)[0])
        verdict = "恶意" if prob >= threshold else "良性"
        return (path_str, prob, verdict, None)
    except Exception as e:
        return (path_str, None, None, str(e))


def collect_pe_files(target: Path) -> List[Path]:
    if target.is_file():
        return [target]
    if not target.exists() or not target.is_dir():
        raise FileNotFoundError(f"指定路径不存在或不是目录: {target}")
    files: List[Path] = []
    for p in target.rglob("*"):
        if p.is_file() and p.suffix.lower() in PE_SUFFIXES:
            files.append(p)
    return files


def save_results_csv(rows: List[Tuple[str, float, str]], out_path: Path) -> None:
    import csv
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "probability", "verdict"])
        for r in rows:
            writer.writerow(r)


def main():
    start = time.strftime("%Y%m%d_%H%M%S")
    print(f"[+] 扫描开始: {start}")
    print(f"[+] 目标: {PATH_TO_SCAN}")
    print(f"[+] 模型: {MODEL_PATH}")
    print(f"[+] 阈值: {THRESHOLD}")
    print(f"[+] 进程数: {MAX_WORKERS}, 单文件超时(s): {TIMEOUT_SECONDS}")
    print(f"[+] 最多扫描文件数: {MAX_TO_SCAN}")

    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"未找到模型文件: {MODEL_PATH}")

    all_files = collect_pe_files(PATH_TO_SCAN)
    if not all_files:
        print("[!] 未找到任何可识别的 PE 文件。结束。")
        return

    pe_files = all_files[:MAX_TO_SCAN]
    total_files = len(pe_files)
    print(f"[+] 发现 {len(all_files)} 个候选；将处理前 {total_files} 个。")

    results: List[Tuple[str, float, str]] = []
    probs: List[float] = []
    failed = 0
    skipped_due_timeout = 0
    malicious_count = 0
    counter = 0

    with ProcessPoolExecutor(
            max_workers=MAX_WORKERS,
            initializer=_init_worker,
            initargs=(str(MODEL_PATH),),
    ) as ex:
        future_to_path = {ex.submit(_worker_predict, str(p), THRESHOLD): p for p in pe_files}
        remaining = set(future_to_path.keys())

        print("[+] 开始并发预测...")
        while remaining:
            # 等待直到至少有一个完成或超时窗口到
            done, not_done = wait(remaining, timeout=TIMEOUT_SECONDS, return_when=FIRST_COMPLETED)

            if not done:
                # 在超时时间内没有任何任务完成 -> 挑一个未完成任务判为超时跳过
                fut = next(iter(not_done))
                path = future_to_path.get(fut)
                skipped_due_timeout += 1
                cancelled = fut.cancel()  # 若任务尚未开始则可取消；已运行则返回 False
                counter += 1
                idx = counter
                print(f"{idx:4d}/{total_files:4d} {path} -> 超时 {TIMEOUT_SECONDS}s，已跳过 (cancelled={cancelled})")
                remaining.remove(fut)
                continue

            for fut in list(done):
                path = future_to_path.get(fut)
                counter += 1
                idx = counter
                try:
                    fpath, prob, verdict, err = fut.result()  # 已完成，不会阻塞
                    if err is None and prob is not None and verdict is not None:
                        results.append((fpath, prob, verdict))
                        probs.append(prob)
                        if verdict == "恶意":
                            malicious_count += 1
                        print(f"{idx:4d}/{total_files:4d} {fpath} -> {prob:.6f} ({verdict})")
                    else:
                        failed += 1
                        print(f"{idx:4d}/{total_files:4d} {path} -> 预测失败: {err}")
                except Exception as e:
                    failed += 1
                    print(f"{idx:4d}/{total_files:4d} {path} -> 预测失败(异常): {e}")
                finally:
                    remaining.remove(fut)

    # 统计
    if probs:
        import numpy as np
        avg = float(np.mean(probs))
        mx = float(np.max(probs))
        mn = float(np.min(probs))
    else:
        avg = mx = mn = 0.0

    processed = len(probs) + failed + skipped_due_timeout

    print("\n==== 汇总 ====")
    print(f"样本总数(本次处理上限): {total_files}")
    # print(f"实际处理(完成/失败/超时): {processed} = 成功{len(probs)} / 失败{failed} / 超时{skipped_due_timeout}")
    print(f"恶意数量: {malicious_count}")
    print(f"准确率: {max(malicious_count, MAX_TO_SCAN - malicious_count) / processed * 100:.2f}%")
    print(f"平均恶意概率: {avg:.6f}")
    print(f"最大恶意概率: {mx:.6f}")
    print(f"最小恶意概率: {mn:.6f}")

    out_csv = Path(__file__).resolve().parent / f"scan_results_{start}.csv"
    save_results_csv([(r[0], f"{r[1]:.6f}", r[2]) for r in results], out_csv)
    print(f"[+] 结果已保存: {out_csv}")


if __name__ == "__main__":
    main()
