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
import tempfile

# 检查是否是打包后的环境
if hasattr(sys, '_MEIPASS'):
    PARENT_DIR = sys._MEIPASS  # 生产环境
    LOG_DIR = os.path.expanduser("~/.linx-xiling/log/")
else:
    PARENT_DIR = os.path.abspath(os.path.join(
        os.path.dirname(__file__), os.pardir))  # 开发环境
    LOG_DIR = os.path.join(PARENT_DIR, 'log')

# 打包安装后程序目录通常只读，允许通过环境变量把日志写到用户可写目录。
LOG_DIR = os.environ.get('XLIN_SBOM_LOG_DIR') or LOG_DIR

ASSIST_DIR = os.path.join(PARENT_DIR, 'assist')

ASSIST_ORIGINATORS_SEED = os.path.join(ASSIST_DIR, 'originators.json')


def _default_cache_dir() -> str:
    """返回运行期缓存目录。

    安装后的程序目录（如 /usr/share/xlin-sbom）通常为只读，
    originators.json 属于运行期累积的缓存，必须写到用户可写目录。
    """
    xdg_cache_home = os.environ.get('XDG_CACHE_HOME')
    if xdg_cache_home:
        return os.path.join(xdg_cache_home, 'xlin-sbom')
    home = os.path.expanduser('~')
    if home and home != '~' and os.path.isdir(home):
        return os.path.join(home, '.cache', 'xlin-sbom')
    return os.path.join(tempfile.gettempdir(), 'xlin-sbom-%d' % os.getuid())


CACHE_DIR = os.environ.get('XLIN_SBOM_CACHE_DIR') or _default_cache_dir()
ORIGINATORS_CACHE_FILE = os.path.join(CACHE_DIR, 'originators.json')

OSV_SCANNER = os.path.join(PARENT_DIR, 'actions/scanner/osv-scanner/osv-scanner_linux_amd64')
