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
import csv
import logging
import argparse
import subprocess
from helper import PARENT_DIR, LOG_DIR
from helper.json_helper import save_data_to_json
from helper.iso_helper import rpm_packages_scanner
from helper.package_helper import package_scanner
from helper.spdx_sbom_helper import convert_to_spdx


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
    parser.add_argument("--output", "-o", required=True, help="SBOM清单输出目录。")
    parser.add_argument("--disable-tqdm", action='store_true', help="禁用进度条显示。")
    parser.add_argument("--max-workers", type=int,
                        default=None, help="最大并发线程数。")

    return parser.parse_args()


def setup_logging(formatted_utc_time):
    """
    配置日志记录，创建日志文件并设置日志格式和处理器。

    Args:
        formatted_utc_time (str): 格式化后的UTC时间字符串，用于生成日志文件名。

    Returns:
        None: 函数不返回任何内容。
    """

    # 配置日志记录
    os.makedirs(LOG_DIR, exist_ok=True)
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


def mount_iso(iso_path, mnt_dir):
    """
    使用挂载命令将ISO镜像文件挂载到指定的目录。

    Args:
        iso_path (str): ISO镜像文件的路径。路径应指向一个有效的ISO文件。
        mnt_dir (str): 挂载点目录的路径。该目录用于挂载ISO镜像文件。

    Returns:
        None: 函数不返回任何内容。
    """

    try:
        subprocess.run(["fuseiso", iso_path, mnt_dir], check=True)
    except subprocess.CalledProcessError as e:
        raise


def umount_iso(mnt_dir):
    """
    卸载指定目录挂载的ISO镜像。

    Args:
        mnt_dir (str): 要卸载ISO镜像的挂载目录路径。

    Returns:
        None: 函数不返回任何内容。
    """

    try:
        subprocess.run(["fusermount", "-u", mnt_dir], check=True)
    except subprocess.CalledProcessError as e:
        raise


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


def detect_package_system(mnt_dir):
    """
    检测给定挂载目录中是否存在`.rpm`包。

    Args:
        mnt_dir (str): 要检测的挂载目录路径。

    Returns:
        rpm_found: 布尔值，表示是否找到`.rpm`包。
    """

    rpm_found = False

    # 遍历挂载目录及其子目录
    for root, dirs, files in os.walk(mnt_dir):
        for file in files:
            # 检查文件是否以`.rpm`结尾
            if file.endswith('.rpm'):
                rpm_found = True
                break
        # 如果找到任何一种类型的包，则停止搜索
        if rpm_found:
            break

    return rpm_found


def save_sbom(linx_sbom, package_type, filename, utc_timestamp, spdx_timestamp, output_dir):
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

    # 生成 Linx 格式 SBOM
    linx_sbom_dirname = f"linx-sbom_{filename}_{utc_timestamp}"
    linx_sbom_packages_filename = f"packages_{filename}_{utc_timestamp}.json"
    linx_sbom_files_filename = f"files_{filename}_{utc_timestamp}.json"
    linx_sbom_licenses_filename = f"licenses_{filename}_{utc_timestamp}.json"
    linx_sbom_package_relationships_filename = f"package_relationships_{filename}_{utc_timestamp}.json"
    linx_sbom_file_relationships_filename = f"file_relationships_{filename}_{utc_timestamp}.json"
    linx_sbom_path = os.path.join(sbom_path, linx_sbom_dirname)
    os.makedirs(linx_sbom_path, exist_ok=True)

    save_data_to_json(linx_sbom.get('packages_sbom'),
                      f"{linx_sbom_path}/{linx_sbom_packages_filename}")
    save_data_to_json(linx_sbom.get('files_sbom'),
                      f"{linx_sbom_path}/{linx_sbom_files_filename}")
    save_data_to_json(linx_sbom.get('licenses_sbom'),
                      f"{linx_sbom_path}/{linx_sbom_licenses_filename}")
    save_data_to_json(linx_sbom.get('package_relationships_sbom'),
                      f"{linx_sbom_path}/{linx_sbom_package_relationships_filename}")
    save_data_to_json(linx_sbom.get('file_relationships_sbom'),
                      f"{linx_sbom_path}/{linx_sbom_file_relationships_filename}")
    logging.info(f"{linx_sbom_dirname} 已被保存至 {output_dir}")

    # 生成 SPDX 格式 SBOM
    spdx_sbom = convert_to_spdx(
        linx_sbom, filename, spdx_timestamp, package_type)
    spdx_sbom_filename = f"spdx-sbom_{filename}_{utc_timestamp}.json"
    save_data_to_json(spdx_sbom, f"{sbom_path}/{spdx_sbom_filename}")
    logging.info(f"{spdx_sbom_filename} 已被保存至 {output_dir}")


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

    # 配置输出目录
    output_dir = args.output

    # 处理ISO镜像
    if args.iso is not None:
        iso_filename = os.path.splitext(os.path.basename(args.iso))[0]
        mnt_dir = os.path.join(PARENT_DIR, 'mnt', str(formatted_utc_time))

        try:
            os.makedirs(mnt_dir, exist_ok=True)
        except Exception as e:
            logging.error(f"异常抛出: {e}")

        try:
            # 将args.iso中的所有空格前添加转义字符"\"
            iso_path = args.iso.replace(' ', '\\ ')
            mount_iso(iso_path, mnt_dir)

            is_rpm = detect_package_system(mnt_dir)
            package_type = "unknown"
            if is_rpm:
                package_type = "rpm"
                logging.info("侦测到RPM包系统")
                linx_sbom = rpm_packages_scanner(
                    mnt_dir, iso_filename, spdx_utc_time, args.disable_tqdm, args.max_workers)
            else:
                logging.error("未侦测到有效的包系统")
                sys.exit(1)

            save_sbom(linx_sbom, package_type, iso_filename,
                      formatted_utc_time, spdx_utc_time, output_dir)
            logging.info("Linx SBOM 生成完成")
        except Exception as e:
            logging.error(f"异常抛出: {e}")

        finally:
            try:
                umount_iso(mnt_dir)
                os.rmdir(mnt_dir)
            except Exception as e:
                logging.error(f"异常抛出: {e}")

    # 处理软件包
    elif args.package is not None:
        package_path = args.package.replace(' ', '\\ ')
        pkg_filename = os.path.splitext(os.path.basename(package_path))[0]

        package_type = "unknown"
        if package_path.endswith('.rpm'):
            package_type = "rpm"
            logging.info("侦测到RPM包")
        elif package_path.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar', '.zip')):
            package_type = "source"
            logging.info("侦测到源码包")
        else:
            logging.error("未侦测到有效的包")
            sys.exit(1)

        linx_sbom = package_scanner(package_path, package_type, spdx_utc_time)
        save_sbom(linx_sbom, package_type, pkg_filename, formatted_utc_time, spdx_utc_time, output_dir)
        logging.info("Linx SBOM 生成完成")



if __name__ == "__main__":
    main()
