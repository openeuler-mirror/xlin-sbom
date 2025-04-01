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


def calculate_sha1(file):
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


def calculate_md5(file):
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


def read_data_from_json(json_file_path):
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


def save_data_to_json(data, json_file_path):
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


def remove_duplicates(list):
    """
    从给定的列表中移除具有重复ID的项，并返回一个新列表，其中每个ID只出现一次。

    Args:
        list (list of dict): 包含字典元素的列表，每个字典必须有'id'键用于唯一标识。

    Returns:
        list of dict: 不含重复ID项的新列表。
    """

    unique_list = []
    seen_ids = set()
    for item in list:
        item_id = item.get("id")
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            unique_list.append(item)
    return unique_list