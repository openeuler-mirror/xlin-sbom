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
