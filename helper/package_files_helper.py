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
import rpmfile
from typing import List, Dict, Any


def rpm_files_scanner(package_path: str) -> List[Dict[str, Any]]:
    """
    扫描RPM包中的文件信息并构建文件列表。

    Args:
        package_path (str): RPM包的路径。

    Returns:
        list: 包含文件信息的列表，每个元素是一个字典，包含文件ID、名称、路径和校验信息。
    """

    # 打开RPM文件并读取头部信息
    with rpmfile.open(package_path) as rpm:
        header = rpm.headers

        # 使用get()方法检查必要的键是否存在，并且不为空
        dirnames = header.get('dirnames', [])
        basenames = header.get('basenames', [])
        dirindexes = header.get('dirindexes', [])
        filemd5s = header.get('filemd5s', [])

        # 将单个元素转换为列表
        if isinstance(dirnames, (bytes, str)):
            dirnames = [dirnames]
        if isinstance(basenames, (bytes, str)):
            basenames = [basenames]
        if isinstance(dirindexes, int):
            dirindexes = [dirindexes]
        if isinstance(filemd5s, (bytes, str)):
            filemd5s = [filemd5s]

        # 构建文件路径和校验信息
        file_list = []
        for i in range(len(basenames)):
            # filemd5s[i]为空代表非文件，跳过
            if not filemd5s[i]:
                continue
            file_path = dirnames[dirindexes[i]].decode(
                'utf-8') + basenames[i].decode('utf-8')
            id_md5 = hashlib.md5(file_path.encode()).hexdigest()[:12]
            file_info = {
                "id": f"File-{basenames[i].decode('utf-8')}-{id_md5}",
                "name": basenames[i].decode('utf-8'),
                "path": file_path,
                "checksums": {
                    "algorithm": "MD5",
                    "value": filemd5s[i].decode('utf-8')
                }
            }
            file_list.append(file_info)

        return file_list
