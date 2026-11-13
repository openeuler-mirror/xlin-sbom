# Copyright 2025 Linx Software, Inc.
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

"""基于系统 rpm 组件读取 RPM 包头与 payload。

此前使用第三方纯 Python 包 rpmfile，发行版仓库没有对应包，导致安装后
必须把依赖放进 vendor。这里改用系统提供的 python3-rpm（rpm 绑定）读取
包头，并用 rpm 自带的 rpm2cpio 解出 payload 后按 newc cpio 格式解析。
"""

import importlib
import io
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, Iterator

_HEADER_TAGS = (
    'name', 'version', 'release', 'url', 'arch', 'sourcerpm',
    'license', 'copyright', 'description', 'requirename', 'provides',
    'dirnames', 'basenames', 'dirindexes', 'filemd5s',
    'longfilesizes', 'filesizes', 'fileinodes', 'filedevices',
    'filedigestalgo',
)

_CPIO_HEADER_SIZE = 110
_CPIO_MAGICS = (b'070701', b'070702')


class RpmMember:
    """payload 中的单个成员，接口与 rpmfile.RPMFile 的成员保持一致。"""

    __slots__ = ('name', 'size', 'mode', '_data')

    def __init__(self, name: str, size: int, mode: int, data: bytes):
        self.name = name
        self.size = size
        self.mode = mode
        self._data = data

    def read(self) -> bytes:
        return self._data


def _read_header(path: str) -> Dict[str, Any]:
    try:
        rpm = importlib.import_module('rpm')
    except ImportError as exc:  # pragma: no cover - 依赖缺失时的明确提示
        raise RuntimeError(
            "读取 RPM 包需要系统提供 python3-rpm（rpm 的 Python 绑定）") from exc

    fd = os.open(path, os.O_RDONLY)
    try:
        transaction = rpm.TransactionSet()
        transaction.setVSFlags(
            rpm.RPMVSF_MASK_NODIGESTS | rpm.RPMVSF_MASK_NOSIGNATURES)
        header = transaction.hdrFromFdno(fd)
    finally:
        os.close(fd)

    headers: Dict[str, Any] = {}
    for tag in _HEADER_TAGS:
        try:
            value = header[tag]
        except (KeyError, TypeError, ValueError):
            continue
        if value is not None:
            headers[tag] = value
    # 兼容 rpmfile 的字段命名：copyright 与 license 是同一个 RPM tag。
    if 'license' in headers:
        headers.setdefault('copyright', headers['license'])
    return headers


def _read_exact(stream, size: int) -> bytes:
    data = stream.read(size)
    if data is None:
        data = b''
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError("cpio 数据提前结束")
        data += chunk
    return data


def _iter_cpio_members(stream) -> Iterator[RpmMember]:
    while True:
        header = stream.read(_CPIO_HEADER_SIZE)
        if not header:
            return
        if len(header) < _CPIO_HEADER_SIZE:
            raise ValueError("cpio 头部不完整")
        if header[:6] not in _CPIO_MAGICS:
            raise ValueError("不支持的 cpio 格式: %r" % header[:6])

        fields = [
            int(header[6 + index * 8:14 + index * 8], 16)
            for index in range(13)
        ]
        mode = fields[1]
        file_size = fields[6]
        name_size = fields[11]

        name_bytes = _read_exact(stream, name_size).rstrip(b'\x00')
        name_padding = (-(_CPIO_HEADER_SIZE + name_size)) % 4
        if name_padding:
            _read_exact(stream, name_padding)

        if name_bytes == b'TRAILER!!!':
            return

        data = _read_exact(stream, file_size) if file_size else b''
        data_padding = (-file_size) % 4
        if data_padding:
            _read_exact(stream, data_padding)

        yield RpmMember(
            name=name_bytes.decode('utf-8', 'surrogateescape'),
            size=file_size,
            mode=mode,
            data=data,
        )


class RpmReader:
    """读取 RPM 包头与 payload，使用完毕后必须 close()。"""

    def __init__(self, path: str):
        self.path = path
        self.headers = _read_header(path)
        self._process = None
        self._members = None

    def getmembers(self) -> Iterator[RpmMember]:
        if self._members is not None:
            return self._members

        rpm2cpio = shutil.which('rpm2cpio')
        if rpm2cpio is None:
            raise RuntimeError("读取 RPM payload 需要系统提供 rpm2cpio（rpm 包）")

        self._process = subprocess.Popen(
            [rpm2cpio, self.path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._members = _iter_cpio_members(self._process.stdout)
        return self._members

    def extractfile(self, member: RpmMember) -> io.BytesIO:
        return io.BytesIO(member.read())

    def close(self) -> None:
        process = self._process
        self._process = None
        self._members = None
        if process is None:
            return
        if process.stdout is not None:
            process.stdout.close()
        stderr = b''
        if process.stderr is not None:
            stderr = process.stderr.read()
            process.stderr.close()
        return_code = process.wait()
        if return_code != 0:
            logging.warning(
                "rpm2cpio 读取 %s 失败（返回码 %s）: %s",
                self.path, return_code,
                stderr.decode('utf-8', 'replace').strip())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


def open_rpm(path: str) -> RpmReader:
    """打开 RPM 包，返回与 rpmfile.open 类似的可迭代读取器。"""

    return RpmReader(path)
