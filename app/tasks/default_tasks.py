"""Register default GUI tasks by delegating to the scripts/ implementations."""

from typing import Callable, Dict, Tuple

from .registry import register_task

from scripts.task_data_cleaning import data_cleaning_task
from scripts.task_feature_extraction import extract_features_task
from scripts.task_feature_vectorization import feature_vector_task
from scripts.task_file_info import file_info_task
from scripts.task_install_dependencies import install_dependencies_task
from scripts.task_model_prediction import model_prediction_task
from scripts.task_model_testing import test_model_task
from scripts.task_model_training import train_model_task

TaskFunc = Callable[[Tuple, Callable[[int], None], Callable[[str], None]], None]

_TASK_IMPLEMENTATIONS: Dict[str, TaskFunc] = {
    "文件信息": file_info_task,
    "提取特征": extract_features_task,
    "特征转换": feature_vector_task,
    "训练模型": train_model_task,
    "安装依赖": install_dependencies_task,
    "数据清洗": data_cleaning_task,
    "模型预测": model_prediction_task,
    "测试模型": test_model_task,
}


for task_name, func in _TASK_IMPLEMENTATIONS.items():
    register_task(task_name)(func)

