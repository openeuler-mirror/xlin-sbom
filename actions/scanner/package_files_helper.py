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
import logging
import os
from actions.scanner.rpm_reader import open_rpm
from typing import List, Dict, Any

from actions.data_helper import calculate_file_checksums


RPM_DIGEST_ALGORITHMS = {
    0: "MD5", 1: "MD5", 2: "SHA1", 8: "SHA256", 9: "SHA384",
    10: "SHA512", 11: "SHA224",
}


def rpm_digest_algorithm(value: Any) -> str:
    """RPM 的旧 filemd5s 字段实际使用 FILEDIGESTALGO 指定的算法。"""

    if value in (None, "", "(none)"):
        value = 0
    if isinstance(value, (list, tuple)):
        value = value[0] if value else 0
    try:
        return RPM_DIGEST_ALGORITHMS.get(int(value), "NOASSERTION")
    except (TypeError, ValueError):
        return "NOASSERTION"


def _header_list(value: Any) -> list:
    if isinstance(value, (list, tuple)):
        return list(value)
    return [] if value is None else [value]


def _header_text(value: Any) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def rpm_files_scanner(package_path: str) -> List[Dict[str, Any]]:
    """
    扫描RPM包中的文件信息并构建文件列表。

    Args:
        package_path (str): RPM包的路径。

    Returns:
        list: 包含文件信息的列表，每个元素是一个字典，包含文件ID、名称、路径和校验信息。
    """

    # 打开RPM文件并读取头部信息
    with open_rpm(package_path) as rpm:
        header = rpm.headers

        # 使用get()方法检查必要的键是否存在，并且不为空
        dirnames = _header_list(header.get('dirnames'))
        basenames = _header_list(header.get('basenames'))
        dirindexes = _header_list(header.get('dirindexes'))
        filemd5s = _header_list(header.get('filemd5s'))
        filesizes = _header_list(header.get('longfilesizes', header.get('filesizes')))
        inodes = _header_list(header.get('fileinodes'))
        devices = _header_list(header.get('filedevices'))
        algorithm = rpm_digest_algorithm(header.get('filedigestalgo'))

        # 构建文件路径和校验信息
        file_list = []
        file_indexes = {}
        hardlink_groups = {}
        for i in range(len(basenames)):
            # filemd5s[i]为空代表非文件，跳过
            if i >= len(filemd5s) or not filemd5s[i]:
                continue
            file_path = _header_text(dirnames[dirindexes[i]]) + _header_text(basenames[i])
            id_md5 = hashlib.md5(file_path.encode()).hexdigest()[:12]
            file_info = {
                "id": f"File-{_header_text(basenames[i])}-{id_md5}",
                "name": _header_text(basenames[i]),
                "path": file_path,
                "checksums": {
                    "algorithm": algorithm,
                    "value": _header_text(filemd5s[i])
                }
            }
            file_list.append(file_info)
            file_indexes[file_path] = (file_info, i)
            if i < len(inodes) and i < len(devices):
                hardlink_groups.setdefault((devices[i], inodes[i]), []).append(file_info)

        # 按 payload 顺序读取。CPIO 硬链接只有一个成员存储实际内容，不能
        # 将其他 size=0 的占位成员误当空文件来计算摘要。
        for member in rpm.getmembers():
            path = "/" + os.path.normpath(member.name).lstrip("/")
            indexed = file_indexes.get(path)
            if indexed is None:
                continue
            file_info, index = indexed
            expected_size = filesizes[index] if index < len(filesizes) else None
            if expected_size is not None and member.size != expected_size:
                continue
            with rpm.extractfile(member) as source:
                sha1 = calculate_file_checksums(source)["SHA1"]
            group = [file_info]
            if index < len(inodes) and index < len(devices):
                group = hardlink_groups[(devices[index], inodes[index])]
            for linked_file in group:
                linked_file["additional_checksums"] = [{"algorithm": "SHA1", "value": sha1}]

        for file_info in file_list:
            if "additional_checksums" not in file_info:
                logging.warning("RPM 文件没有可读取的 payload，未生成 SHA1: %s", file_info["path"])

        return file_list


def deb_files_scanner(deb) -> List[Dict[str, Any]]:
    """
    扫描DEB包中的文件信息并构建文件列表。

    Args:
        deb (debian.debfile.DebFile): 已打开的 DEB 包对象。

    Returns:
        list: 包含文件信息的列表，每个元素是一个字典，包含文件ID、名称、路径和校验信息。
    """

    file_list = []
    data_tar = deb.data.tgz()
    file_members = data_tar.getmembers()

    # 筛选文件成员中的文件（非目录），构造文件名和路径信息，并计算SHA1哈希值
    for member in file_members:
        if member.isfile():
            # python-debian 的成员名称是不可哈希的 str 子类，输出统一为普通字符串。
            file_path = str(member.name)
            extracted_file = data_tar.extractfile(member)
            if extracted_file is None:
                continue
            with extracted_file:
                digests = calculate_file_checksums(extracted_file)

            # 创建一个MD5哈希对象
            id_md5 = hashlib.md5(file_path.encode()).hexdigest()

            # 构建文件信息字典
            file_info = {
                "id": f"File-{os.path.basename(file_path)}-{id_md5[:12]}",
                "name": os.path.basename(file_path),
                "path": file_path,
                "checksums": {
                    "algorithm": "MD5",
                    "value": digests["MD5"]
                },
                "additional_checksums": [{"algorithm": "SHA1", "value": digests["SHA1"]}]
            }
            file_list.append(file_info)

    return file_list
