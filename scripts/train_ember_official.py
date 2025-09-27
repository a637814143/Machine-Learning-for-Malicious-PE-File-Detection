#!/usr/bin/env python3
"""官方 EMBER 训练流程脚本。

该脚本紧跟 EMBER 官方仓库提供的 ``init_ember.py`` / ``ember.train_model`` 实现，
用于在包含原始特征 JSON 的目录中执行以下操作：

1. 如果尚未生成 ``X_train.dat``、``y_train.dat`` 等向量化特征文件，则调用
   :func:`ember.create_vectorized_features` 完成转换；
2. 按需生成 metadata CSV；
3. 使用官方推荐的 LightGBM 超参数训练模型，并保存 ``model.txt``。

运行示例::

    python scripts/train_ember_official.py -t -m /path/to/ember2018

脚本会将训练得到的模型保存到 ``model.txt``（或 ``--output`` 指定的路径），
从而与 EMBER 官方流程保持一致。
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Dict

import ember

# EMBER 官方脚本中使用的默认 LightGBM 参数
DEFAULT_PARAMS: Dict[str, object] = {
    "boosting": "gbdt",
    "objective": "binary",
    "num_iterations": 1000,
    "learning_rate": 0.05,
    "num_leaves": 2048,
    "max_depth": 15,
    "min_data_in_leaf": 50,
    "feature_fraction": 0.5,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="train_ember_official",
        description="使用 EMBER 官方方法训练 LightGBM 模型",
    )
    parser.add_argument(
        "datadir",
        metavar="DATADIR",
        help="包含 EMBER 原始 JSON 特征的目录",
    )
    parser.add_argument(
        "-v",
        "--featureversion",
        type=int,
        default=2,
        help="EMBER 特征版本（默认为 2）",
    )
    parser.add_argument(
        "-m",
        "--metadata",
        action="store_true",
        help="生成 metadata CSV（与官方脚本一致）",
    )
    parser.add_argument(
        "-t",
        "--train",
        action="store_true",
        help="执行模型训练流程（与官方脚本一致）",
    )
    parser.add_argument(
        "--optimize",
        action="store_true",
        help="调用 ember.optimize_model 进行网格搜索，与官方脚本一致",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="model.txt",
        help="模型输出文件名，默认写入 DATADIR/model.txt",
    )
    return parser.parse_args()


def ensure_vectorized_features(data_dir: str, feature_version: int) -> None:
    """确保向量化特征文件存在，若不存在则调用官方函数生成。"""

    x_train_path = os.path.join(data_dir, "X_train.dat")
    y_train_path = os.path.join(data_dir, "y_train.dat")
    if os.path.exists(x_train_path) and os.path.exists(y_train_path):
        return

    print("未检测到向量化特征，正在调用 ember.create_vectorized_features()...")
    ember.create_vectorized_features(data_dir, feature_version)


def main() -> None:
    args = parse_args()

    if not os.path.isdir(args.datadir):
        raise SystemExit(f"{args.datadir} 不是有效的目录")

    ensure_vectorized_features(args.datadir, args.featureversion)

    if args.metadata:
        print("生成 metadata CSV...")
        ember.create_metadata(args.datadir)

    if args.train:
        params = DEFAULT_PARAMS.copy()
        if args.optimize:
            print("执行参数网格搜索...")
            params = ember.optimize_model(args.datadir)
            print("最佳参数如下：")
            print(json.dumps(params, indent=2, ensure_ascii=False))

        print("按照 EMBER 官方方式训练 LightGBM 模型...")
        model = ember.train_model(args.datadir, params, args.featureversion)

        output_path = args.output
        if not os.path.isabs(output_path):
            output_path = os.path.join(args.datadir, output_path)

        model.save_model(output_path)
        print(f"模型已保存至: {output_path}")
    else:
        print("未指定 --train，脚本仅完成特征准备任务。")


if __name__ == "__main__":
    main()
