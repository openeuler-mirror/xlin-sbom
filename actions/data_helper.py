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

import hashlib
import json
import logging
import os
from actions import ORIGINATORS_CACHE_FILE
from typing import Any, Dict, Iterable, List, Union


def calculate_file_checksums(
    file: Any, algorithms: Iterable[str] = ("MD5", "SHA1")
) -> Dict[str, str]:
    """从真实内容一次性计算指定摘要（默认 MD5、SHA1），不要求流可 seek。"""

    digests = {algorithm: hashlib.new(algorithm.lower()) for algorithm in algorithms}
    for chunk in iter(lambda: file.read(65536), b""):
        for digest in digests.values():
            digest.update(chunk)
    return {algorithm: digest.hexdigest() for algorithm, digest in digests.items()}


def calculate_sha1(file: Any) -> str:
    """
    计算文件的 SHA-1 哈希值。

    Args:
        file (file-like object): 要计算哈希值的文件对象。该对象应该支持 `read` 方法。

    Returns:
        str: 文件的 SHA-1 哈希值（以十六进制字符串形式表示）。
    """

    sha1 = hashlib.sha1()

    chunk = file.read(8192)
    while chunk:
        sha1.update(chunk)
        chunk = file.read(8192)

    return sha1.hexdigest()


def calculate_md5(file: Any) -> str:
    """
    计算文件的 MD5 哈希值。

    Args:
        file (file-like object): 要计算哈希值的文件对象。该对象应该支持 `read` 方法。

    Returns:
        str: 文件的 MD5 哈希值（以十六进制字符串形式表示）。
    """

    md5 = hashlib.md5()

    chunk = file.read(8192)
    while chunk:
        md5.update(chunk)
        chunk = file.read(8192)

    return md5.hexdigest()


def read_data_from_json(json_file_path: str) -> Union[Dict[str, Any], List[Any]]:
    """
    从 JSON 文件中读取数据。

    Args:
        json_file_path (str): JSON 文件的路径。

    Returns:
        dict or list: 从 JSON 文件中读取的数据。可以是字典或列表。
    """

    with open(json_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def save_data_to_json(data: Union[Dict[str, Any], List[Any]], json_file_path: str) -> None:
    """
    将数据保存到 JSON 文件中。

    Args:
        data (dict or list): 要保存的数据，可以是字典或列表。
        json_file_path (str): JSON 文件的路径。

    Returns:
        None
    """
    if data is not None:
        with open(json_file_path, 'w', encoding='utf-8') as json_file:
            json.dump(data, json_file, ensure_ascii=False, indent=4)


def save_originators(data: Union[Dict[str, Any], List[Any]],
                     seed_file_path: str = None) -> None:
    """
    将发起者缓存保存到用户可写目录。

    安装后的程序目录（如 /usr/share/xlin-sbom/assist）通常只读，
    originators.json 是运行期累积的缓存，不能写回安装目录。缓存写入
    失败时只记录告警，不影响本次 SBOM 生成。

    Args:
        data (dict or list): 要保存的发起者数据。
        seed_file_path (str): 兼容旧调用保留的参数，仅用于日志提示。

    Returns:
        None
    """
    if data is None:
        return
    cache_dir = os.path.dirname(ORIGINATORS_CACHE_FILE)
    try:
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        save_data_to_json(data, ORIGINATORS_CACHE_FILE)
    except OSError as exc:
        logging.warning(
            "发起者缓存 %s 写入失败（%s），本次扫描继续，缓存不持久化",
            ORIGINATORS_CACHE_FILE, exc)


def load_originators(seed_file_path: str) -> Union[Dict[str, Any], List[Any]]:
    """
    读取发起者缓存：用户缓存文件存在时优先读取，以延续上次扫描累积的
    数据；否则读取安装目录内的原始 originators.json。缓存文件损坏时
    记录日志并回退到原始文件。

    Args:
        seed_file_path (str): 安装目录内的原始 originators.json 路径。

    Returns:
        dict or list: 发起者数据；两者都不可用时返回空列表。
    """
    if os.path.isfile(ORIGINATORS_CACHE_FILE):
        try:
            return read_data_from_json(ORIGINATORS_CACHE_FILE)
        except (OSError, ValueError) as exc:
            logging.warning(
                "发起者缓存 %s 读取失败（%s），回退到 %s",
                ORIGINATORS_CACHE_FILE, exc, seed_file_path)
    try:
        return read_data_from_json(seed_file_path)
    except OSError as exc:
        logging.warning("读取发起者数据 %s 失败: %s", seed_file_path, exc)
        return []


def remove_duplicates(list_of_dicts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    从给定的列表中移除具有重复ID的项，并返回一个新列表，其中每个ID只出现一次。

    Args:
        list_of_dicts (list of dict): 包含字典元素的列表，每个字典必须有'id'键用于唯一标识。

    Returns:
        list of dict: 不含重复ID项的新列表。
    """
    unique_list = []
    seen_ids = set()
    for item in list_of_dicts:
        item_id = item.get("id")
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            unique_list.append(item)
    return unique_list


def remove_duplicate_files(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """合并同 ID 的文件时优先保留已读取内容的条目，避免 ghost 遮盖真实文件。"""

    unique_files = {}
    for file in files:
        file_id = file.get("id")
        previous = unique_files.get(file_id)
        has_sha1 = any(c.get("algorithm") == "SHA1" and c.get("value")
            for c in file.get("additional_checksums", []))
        previous_has_sha1 = previous is not None and any(
            c.get("algorithm") == "SHA1" and c.get("value")
            for c in previous.get("additional_checksums", []))
        if previous is None or (has_sha1 and not previous_has_sha1):
            unique_files[file_id] = file
    return list(unique_files.values())


def remove_duplicate_relationships(
    relationships: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """关系由两端 ID 和类型共同标识，保留不同类型及不同归属的关系。"""

    unique = []
    seen = set()
    for relationship in relationships:
        key = (relationship["id"], relationship["related_element"], relationship["relationship_type"])
        if key not in seen:
            seen.add(key)
            unique.append(relationship)
    return unique
