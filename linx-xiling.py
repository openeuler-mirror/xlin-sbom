#!/usr/bin/env python3
#
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

import os
import sys
import time
import logging
import argparse
import csv
import copy
from actions import (
    LOG_DIR,
    ASSIST_DIR
)
from actions.data_helper import (
    save_data_to_json,
    read_data_from_json
)
from actions.scanner.iso_helper import (
    scan_iso
)
from actions.scanner.docker_image_helper import scan_docker_image
from actions.scanner.package_helper import package_scanner
from actions.scanner.repo_helper import (
    rpm_repo_scanner,
    deb_repo_scanner,
    find_primary_xml_in_repo,
    find_deb_sources_in_repo
)
from actions.scanner.spdx_sbom_helper import convert_to_spdx


DEFAULT_CONFIG_PATH = os.path.join(ASSIST_DIR, 'config.json')
EXTERNAL_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'config', 'config.json')
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


def parse_arguments():
    """
    解析命令行参数，用于配置扫描源代码包以获取版权和许可证信息的工具。

    Args:
        None

    Returns:
        argparse.Namespace: 包含解析后的命令行参数的对象。
    """

    parser = argparse.ArgumentParser(
        description="对ISO镜像或软件包进行扫描，并生成SBOM清单。")
    # 添加互斥组，用户必须指定 --iso 或者 --package 之一
    mutually_exclusive_group = parser.add_mutually_exclusive_group(
        required=True)
    mutually_exclusive_group.add_argument("--iso", "-i",
                                          help="ISO镜像文件的路径。")
    mutually_exclusive_group.add_argument("--package", "-p",
                                          help="软件包的路径。")
    mutually_exclusive_group.add_argument("--repo", "-r",
                                          help="更新源地址。")
    mutually_exclusive_group.add_argument("--docker", "-d",
                                          help="Docker Hub 镜像名或离线 Docker 镜像 tar 文件路径。")
    parser.add_argument("--output", "-o", required=True, help="SBOM清单输出目录。")
    parser.add_argument("--format", "-f", action='append', choices=("linx", "spdx"),
                        help="SBOM output format. Can be repeated. Defaults to both linx and spdx.")

    return parser.parse_args()


def setup_logging(formatted_utc_time):
    """
    配置日志记录，创建日志文件并设置日志格式和处理器，同时限制日志文件数量，只保留最近的200个。

    Args:
        formatted_utc_time (str): 格式化后的UTC时间字符串，用于生成日志文件名。

    Returns:
        None: 函数不返回任何内容。
    """

    # 创建日志目录
    os.makedirs(LOG_DIR, exist_ok=True)

    # 获取所有日志文件
    log_files = [f for f in os.listdir(
        LOG_DIR) if f.startswith('log_') and f.endswith('.log')]

    # 按创建时间排序（旧文件在前）
    log_files.sort(key=lambda x: os.path.getctime(os.path.join(LOG_DIR, x)))

    # 删除超出的旧日志文件
    max_log_files = 200
    if len(log_files) + 1 > max_log_files:
        files_to_delete = len(log_files) + 1 - max_log_files
        for i in range(files_to_delete):
            file_to_delete = os.path.join(LOG_DIR, log_files[i])
            try:
                os.remove(file_to_delete)
                logging.debug(f"删除日志: {file_to_delete}")
            except Exception as e:
                logging.error(f"删除 {file_to_delete} 时失败: {str(e)}")

    # 创建新日志文件
    log_file = os.path.join(LOG_DIR, f'log_{formatted_utc_time}.log')

    # 创建日志记录器
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # 文件处理器
    file_handler = logging.FileHandler(log_file, mode='w')
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(name)s:%(funcName)s] %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)


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
            "platform": "linux/amd64"
        },
        "source_scan": {
            "include_file_patterns": DEFAULT_SOURCE_INCLUDE_PATTERNS.copy(),
            "exclude_file_patterns": [],
            "brief": False
        }
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
            "source_scan.exclude_file_patterns"):
        return _is_string_list(value)
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


def load_category_dict(category_csv_path):
    """
    从指定路径加载软件包类型CSV文件，并将其内容转换为字典。

    Args:
        category_csv_path (str): CSV文件的路径，其中包含软件包类型信息。

    Returns:
        dict: 包含包名称作为键，类别作为值的字典。类别包括'self_developed', 'modified', 'third_party'。
    """

    try:
        with open(category_csv_path, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            # 检查CSV文件的列标题是否正确
            if reader.fieldnames != ['package', 'category']:
                raise ValueError(
                    "无效的列名，预期 'package' 和 'category'")

            # 定义有效的类别集合
            valid_categories = {'self_developed', 'modified', 'third_party'}
            category_dict = {}
            # 遍历CSV文件中的每一行
            for row in reader:
                # 检查当前行的类别是否有效
                if row['category'] in valid_categories:
                    category_dict[row['package']] = row['category']
                else:
                    raise ValueError(
                        f"无效的类别，预期 'self_developed','modified', 或 'third_party'")

            return category_dict

    except FileNotFoundError:
        logging.error(f"软件包类型CSV文件未找到 - {category_csv_path}")
        sys.exit(1)
    except ValueError as e:
        logging.error(f"异常抛出：{e}")
        sys.exit(1)


def save_sbom(linx_sbom, package_type, filename, utc_timestamp, spdx_timestamp, output_dir, output_formats):
    """
    保存给定的 SBOM 数据到指定目录，并生成 Linx 格式和 SPDX 格式的 SBOM 文件。

    Args:
        linx_sbom (dict): 包含处理后的软件包信息列表，包括 `packages_sbom`, `files_sbom`, `file_relationships_sbom`, `licenses_sbom`。
        package_type (str): 软件包的类型。
        filename (str): 生成的 SBOM 文件的基本名称。
        utc_timestamp (str): UTC 时间戳，用于生成文件名。
        spdx_timestamp (str): SPDX 时间戳，用于生成 SPDX SBOM。
        output_dir (str): 保存 SBOM 文件的目标目录。

    Returns:
        None: 函数不返回任何内容。
    """

    sbom_path = os.path.join(output_dir, filename)
    os.makedirs(sbom_path, exist_ok=True)

    if "linx" in output_formats:
        linx_sbom_dirname = f"linx-sbom_{filename}_{utc_timestamp}"
        linx_sbom_packages_filename = f"packages_{filename}_{utc_timestamp}.json"
        linx_sbom_files_filename = f"files_{filename}_{utc_timestamp}.json"
        linx_sbom_licenses_filename = f"licenses_{filename}_{utc_timestamp}.json"
        linx_sbom_package_relationships_filename = f"package_relationships_{filename}_{utc_timestamp}.json"
        linx_sbom_file_relationships_filename = f"file_relationships_{filename}_{utc_timestamp}.json"
        linx_sbom_path = os.path.join(sbom_path, linx_sbom_dirname)
        os.makedirs(linx_sbom_path, exist_ok=True)

        save_data_to_json(linx_sbom.get('packages_sbom'),
                          os.path.join(linx_sbom_path, linx_sbom_packages_filename))
        save_data_to_json(linx_sbom.get('files_sbom'),
                          os.path.join(linx_sbom_path, linx_sbom_files_filename))
        save_data_to_json(linx_sbom.get('licenses_sbom'),
                          os.path.join(linx_sbom_path, linx_sbom_licenses_filename))
        save_data_to_json(linx_sbom.get('package_relationships_sbom'),
                          os.path.join(linx_sbom_path, linx_sbom_package_relationships_filename))
        save_data_to_json(linx_sbom.get('file_relationships_sbom'),
                          os.path.join(linx_sbom_path, linx_sbom_file_relationships_filename))
        logging.info(f"{linx_sbom_dirname} 已被保存至 {output_dir}")

    if "spdx" in output_formats:
        spdx_sbom = convert_to_spdx(
            linx_sbom, filename, spdx_timestamp, package_type)
        spdx_sbom_filename = f"spdx-sbom_{filename}_{utc_timestamp}.json"
        save_data_to_json(spdx_sbom, os.path.join(sbom_path, spdx_sbom_filename))
        logging.info(f"{spdx_sbom_filename} 已被保存至 {output_dir}")


def resolve_output_formats(formats):
    """解析用户指定的 SBOM 输出格式。

    Args:
        formats (list[str] | None): 命令行传入的输出格式列表。

    Returns:
        list[str]: 去重后的输出格式列表。未传入时返回默认格式。
    """

    return list(dict.fromkeys(formats or ["linx", "spdx"]))


def main():
    """
    主函数，负责解析命令行参数、设置日志记录系统、处理ISO镜像或软件包，并生成SBOM。

    Args:
        无直接参数。命令行参数通过 `parse_arguments()` 函数解析后传递给本函数。

    Returns:
        None: 函数不返回任何内容。
    """

    # 解析命令行参数
    args = parse_arguments()

    # 获取 UTC 时间并格式化
    timestamp = time.time()
    utc_time_tuple = time.gmtime(timestamp)
    spdx_utc_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", utc_time_tuple)
    formatted_utc_time = time.strftime("%Y%m%d%H%M%S", utc_time_tuple)

    # 设置日志记录系统
    setup_logging(formatted_utc_time)
    config = load_scan_config()
    runtime_options = resolve_runtime_options(config)
    output_formats = resolve_output_formats(args.format)

    # 配置输出目录
    output_dir = args.output

    # 处理ISO镜像
    if args.iso is not None:
        filename = os.path.splitext(os.path.basename(args.iso))[0]
        try:
            linx_sbom, package_type = scan_iso(
                args.iso, filename, spdx_utc_time,
                runtime_options["disable_tqdm"],
                runtime_options["max_workers"])
        except Exception as e:
            logging.error(f"异常抛出: {e}")
            sys.exit(1)

    # 处理软件包
    elif args.package is not None:
        package_path = args.package
        filename = os.path.splitext(os.path.basename(package_path))[0]

        package_type = "unknown"
        if package_path.endswith(('.src.rpm', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar', '.zip', '.dsc')):
            package_type = "source"
            logging.info("侦测到源码包")
        elif package_path.endswith('.deb'):
            package_type = "deb"
            logging.info("侦测到DEB包")
        elif package_path.endswith('.rpm'):
            package_type = "rpm"
            logging.info("侦测到RPM包")
        else:
            logging.error("未侦测到有效的包")
            sys.exit(1)

        linx_sbom = package_scanner(
            package_path, package_type, spdx_utc_time,
            runtime_options["include"],
            runtime_options["exclude"],
            runtime_options["max_workers"],
            runtime_options["disable_tqdm"],
            runtime_options["brief"])

    # 处理更新源
    elif args.repo is not None:
        filename = "repo"
        package_type = "repo"

        # 查找 primary.xml.gz 文件
        repo_url = args.repo.rstrip('/') + '/'
        primary_xml_url = find_primary_xml_in_repo(repo_url)
        sources_file_url = find_deb_sources_in_repo(repo_url)
        if primary_xml_url:
            linx_sbom = rpm_repo_scanner(
                primary_xml_url, repo_url, spdx_utc_time,
                runtime_options["disable_tqdm"])
        elif sources_file_url:
            linx_sbom = deb_repo_scanner(
                sources_file_url, repo_url, spdx_utc_time,
                runtime_options["disable_tqdm"])
        else:
            logging.error(f"未侦测到有效的更新源地址")
            sys.exit(1)

    # 处理 Docker 镜像
    elif args.docker is not None:
        try:
            linx_sbom, package_type, filename = scan_docker_image(
                args.docker, spdx_utc_time,
                runtime_options["platform"],
                runtime_options["disable_tqdm"])
        except Exception as e:
            logging.error(f"异常抛出: {e}")
            sys.exit(1)

    # 保存SBOM
    save_sbom(linx_sbom, package_type, filename,
              formatted_utc_time, spdx_utc_time, output_dir,
              output_formats)
    logging.info("Linx SBOM 生成完成")


if __name__ == "__main__":
    main()
