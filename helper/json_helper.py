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

import json


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
