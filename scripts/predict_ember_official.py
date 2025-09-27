#!/usr/bin/env python3
"""使用 EMBER 官方模型预测单个或多个 PE 文件是否为恶意样本的脚本。

该脚本读取 ``train_ember_official.py`` 生成的 LightGBM ``model.txt``，
通过 :class:`ember.PEFeatureExtractor` 从 PE 文件中提取特征，再调用模型
输出恶意概率与标签判断结果，完全遵循 EMBER 官方 API。
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Iterable, List

import ember
import lightgbm as lgb
import numpy as np


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="predict_ember_official",
        description="加载 EMBER 模型并对给定 PE 文件进行预测",
    )
    parser.add_argument(
        "model",
        metavar="MODEL",
        help="使用 train_ember_official.py 训练得到的 model.txt 路径",
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="PE",
        help="待预测的一个或多个 PE 文件路径",
    )
    parser.add_argument(
        "-v",
        "--featureversion",
        type=int,
        default=2,
        help="EMBER 特征版本（默认 2，与官方一致）",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=float,
        default=0.5,
        help="判定为恶意样本的概率阈值，默认 0.5",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="以 JSON 格式输出预测结果，方便脚本化处理",
    )
    return parser.parse_args()


def load_model(model_path: str | os.PathLike[str]) -> lgb.Booster:
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"模型文件不存在: {model_path}")
    return lgb.Booster(model_file=str(model_path))


def extract_features(
    extractor: ember.PEFeatureExtractor, path: str | os.PathLike[str]
) -> np.ndarray:
    with open(path, "rb") as f:
        bytez = f.read()
    return extractor.feature_vector(bytez)


def batch_predict(
    model: lgb.Booster,
    extractor: ember.PEFeatureExtractor,
    files: Iterable[str],
) -> List[tuple[str, float]]:
    features: List[np.ndarray] = []
    valid_paths: List[str] = []
    for file_path in files:
        try:
            features.append(extract_features(extractor, file_path))
            valid_paths.append(file_path)
        except Exception as exc:  # noqa: BLE001 - 保留原始异常信息便于排查
            print(f"提取特征失败，跳过 {file_path}: {exc}")
    if not features:
        return []
    feature_matrix = np.vstack(features)
    scores = model.predict(feature_matrix)
    # LightGBM 返回 shape=(n,) 的 ndarray
    return list(zip(valid_paths, scores.tolist()))


def main() -> None:
    args = parse_args()

    model = load_model(args.model)
    extractor = ember.PEFeatureExtractor(feature_version=args.featureversion)

    predictions = batch_predict(model, extractor, args.files)
    if not predictions:
        raise SystemExit("未获得任何有效预测结果，请检查输入文件。")

    threshold = args.threshold
    results = []
    for path, score in predictions:
        label = "malicious" if score >= threshold else "benign"
        results.append({
            "file": str(Path(path)),
            "score": float(score),
            "label": label,
            "threshold": threshold,
        })

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for item in results:
            print(
                f"{item['file']}: score={item['score']:.6f}, "
                f"threshold={threshold:.2f} -> {item['label']}"
            )


if __name__ == "__main__":
    main()
