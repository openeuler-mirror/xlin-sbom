# Copyright 2024 Linx Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import logging
import os

from actions import ASSIST_DIR
from actions.data_helper import read_data_from_json


DEFAULT_CONFIG_PATH = os.path.join(ASSIST_DIR, "config.json")
EXTERNAL_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "config.json",
)
DEFAULT_SOURCE_INCLUDE_PATTERNS = [
    "*.c",
    "*.h",
    "*.cpp",
    "*.hpp",
    "*.cc",
    "*.hh",
    "*.java",
    "*.py",
    "*.pyw",
    "*.rs",
    "*.pl",
    "*.pm",
    "*.js",
    "*.ts",
    "*.jsx",
    "*.dart",
    "*.ex",
    "*.exs",
    "*.go",
    "*.hs",
    "*.cs",
    "*.vb",
    "*.php",
    "*.r",
    "*.R",
    "*.rb",
    "*license*",
    "*LICENSE*",
    "*copyright*",
    "*COPYRIGHT*",
    "*copying*",
    "*COPYING*",
]


def merge_configs(default_config, external_config, path=""):
    """递归合并默认配置和外部配置。

    Args:
        default_config (dict): 默认配置。
        external_config (dict): 外部覆盖配置。
        path (str): 当前递归路径，用于日志提示。

    Returns:
        dict: 合并后的配置。
    """

    if not isinstance(external_config, dict):
        logging.warning("外部配置不是 JSON 对象，已忽略")
        return copy.deepcopy(default_config)

    merged = copy.deepcopy(default_config)
    for key, external_value in external_config.items():
        current_path = f"{path}.{key}" if path else key
        if key not in merged:
            logging.warning(f"未知配置项 '{current_path}'，已忽略")
            continue

        default_value = merged[key]
        if isinstance(default_value, dict) and isinstance(external_value, dict):
            merged[key] = merge_configs(
                default_value, external_value, current_path)
        elif isinstance(default_value, dict):
            logging.warning(
                f"配置项类型冲突 '{current_path}'，已忽略外部配置")
        else:
            merged[key] = external_value
    return merged


def get_builtin_config():
    """获取内置默认扫描配置。

    Returns:
        dict: 内置默认配置。
    """

    return {
        "scan": {
            "disable_tqdm": False,
            "max_workers": None,
            "platform": "linux/amd64",
        },
        "source_scan": {
            "include_file_patterns": DEFAULT_SOURCE_INCLUDE_PATTERNS.copy(),
            "exclude_file_patterns": [],
            "brief": False,
        },
        "elastic_search": {
            "hosts": [
                "http://host.docker.internal:9200",
            ],
            "index_name": "osv_vulnerability_db",
            "api_key": "YTgzZE1Kd0JkT1NXNWtDRmxpWmc6cjZLRDBMeW9kZ2YyS1p6cmRUREtXdw==",
        },
    }


def _is_string_list(value):
    """判断配置值是否为字符串列表。

    Args:
        value (object): 待检查的配置值。

    Returns:
        bool: 若值为字符串列表则返回 True。
    """

    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_valid_config_value(path, value):
    """校验单个配置项的值。

    Args:
        path (str): 配置项路径。
        value (object): 配置项值。

    Returns:
        bool: 配置项合法时返回 True。
    """

    if path in ("scan.disable_tqdm", "source_scan.brief"):
        return isinstance(value, bool)
    if path == "scan.max_workers":
        return value is None or (
            isinstance(value, int) and not isinstance(value, bool) and value > 0)
    if path == "scan.platform":
        return isinstance(value, str) and bool(value.strip())
    if path in (
            "source_scan.include_file_patterns",
            "source_scan.exclude_file_patterns",
            "elastic_search.hosts"):
        return _is_string_list(value)
    if path in ("elastic_search.index_name", "elastic_search.api_key"):
        return isinstance(value, str)
    return True


def normalize_config(config, default_config, path=""):
    """按默认配置结构规范化扫描配置。

    Args:
        config (dict): 待规范化的配置。
        default_config (dict): 字段回退使用的默认配置。
        path (str): 当前递归路径。

    Returns:
        dict: 规范化后的配置。
    """

    if not isinstance(config, dict):
        logging.warning("配置文件内容不是 JSON 对象，已使用默认配置")
        return copy.deepcopy(default_config)

    normalized = {}
    for key, default_value in default_config.items():
        current_path = f"{path}.{key}" if path else key
        if key not in config:
            normalized[key] = copy.deepcopy(default_value)
            continue

        value = config[key]
        if isinstance(default_value, dict):
            if isinstance(value, dict):
                normalized[key] = normalize_config(
                    value, default_value, current_path)
            else:
                logging.warning(f"配置项 '{current_path}' 类型错误，已使用默认值")
                normalized[key] = copy.deepcopy(default_value)
        elif _is_valid_config_value(current_path, value):
            normalized[key] = value
        else:
            logging.warning(f"配置项 '{current_path}' 值无效，已使用默认值")
            normalized[key] = copy.deepcopy(default_value)

    for key in config:
        if key not in default_config:
            current_path = f"{path}.{key}" if path else key
            logging.warning(f"未知配置项 '{current_path}'，已忽略")
    return normalized


def load_scan_config(config_path=EXTERNAL_CONFIG_PATH):
    """加载扫描配置。

    Args:
        config_path (str | None): 外部配置文件路径。

    Returns:
        dict: 合并后的扫描配置。
    """

    builtin_config = get_builtin_config()
    try:
        default_config = normalize_config(
            read_data_from_json(DEFAULT_CONFIG_PATH), builtin_config)
    except Exception as e:
        logging.warning(f"默认配置文件加载失败，将使用内置默认值: {e}")
        default_config = builtin_config

    if config_path and os.path.exists(config_path):
        try:
            external_config = read_data_from_json(config_path)
            config = normalize_config(
                merge_configs(default_config, external_config),
                default_config)
            logging.info(f"外部配置已加载: {config_path}")
        except Exception as e:
            logging.warning(f"外部配置加载失败，将使用默认配置: {e}")
            config = default_config
    else:
        if config_path:
            logging.warning(f"外部配置文件不存在，将使用默认配置: {config_path}")
        config = default_config
    return config


def resolve_runtime_options(config):
    """根据配置解析运行选项。

    Args:
        config (dict): 扫描配置。

    Returns:
        dict: 运行时选项。
    """

    scan_config = config.get("scan", {})
    source_config = config.get("source_scan", {})
    return {
        "include": source_config.get("include_file_patterns"),
        "exclude": source_config.get("exclude_file_patterns"),
        "brief": source_config.get("brief"),
        "disable_tqdm": scan_config.get("disable_tqdm"),
        "max_workers": scan_config.get("max_workers"),
        "platform": scan_config.get("platform"),
    }
