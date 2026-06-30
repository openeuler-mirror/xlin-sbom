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
from typing import List, Dict, Any, Tuple


def _safe_decode(value, encoding: str = 'utf-8') -> str:
    """
    安全地将字节串解码为字符串，遇到非法字节时以替换字符代替，避免抛出异常。

    Args:
        value (bytes or str or None): 需要解码的值。
        encoding (str): 解码使用的编码，默认 utf-8。

    Returns:
        str: 解码后的字符串；输入为 None 时返回空字符串。
    """
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    return value.decode(encoding, errors='replace')


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
            # 安全解码路径与文件名，避免非 UTF-8 编码导致异常
            dir_name = _safe_decode(dirnames[dirindexes[i]])
            base_name = _safe_decode(basenames[i])
            file_path = dir_name + base_name
            id_hash = hashlib.sha256(file_path.encode()).hexdigest()[:12]
            file_info = {
                "id": f"File-{base_name}-{id_hash}",
                "name": base_name,
                "path": file_path,
                "checksums": {
                    "algorithm": "MD5",
                    "value": _safe_decode(filemd5s[i])
                }
            }
            file_list.append(file_info)

        return file_list


def deb_files_scanner(package_path) -> Tuple[Any, List[Dict[str, Any]]]:
    """
    扫描DEB包中的文件信息并构建文件列表。

    Args:
        package_path (str): DEB包的路径。

    Returns:
        tuple: 包含两个元素的元组：
            - `deb` (debian.debfile.DebFile): 打开的DEB文件对象。
            - `file_list` (list): 包含文件信息的列表，每个元素是一个字典，包含文件ID、名称、路径和校验信息。
    """

    import debian.debfile
    import os
    from actions.data_helper import calculate_sha256

    file_list = []

    # 使用debian.debfile库打开DEB文件
    deb = debian.debfile.DebFile(package_path)

    # 获取DEB包内所有文件成员
    file_members = deb.data.tgz().getmembers()

    # 筛选文件成员中的文件（非目录），构造文件名和路径信息，并计算SHA256哈希值
    for member in file_members:
        if member.isfile():
            file_path = member.name
            with deb.data.tgz().extractfile(member) as f:
                file_sha256 = calculate_sha256(f)

            # 根据文件路径生成用于ID的SHA256哈希
            id_hash = hashlib.sha256(file_path.encode()).hexdigest()

            # 构建文件信息字典
            file_info = {
                "id": f"File-{os.path.basename(file_path)}-{id_hash[:12]}",
                "name": os.path.basename(file_path),
                "path": file_path,
                "checksums": {
                    "algorithm": "SHA256",
                    "value": file_sha256
                }
            }
            file_list.append(file_info)

    # 返回DEB文件对象和文件信息列表
    return deb, file_list
