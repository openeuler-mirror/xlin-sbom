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

# 检查是否是打包后的环境
if hasattr(sys, '_MEIPASS'):
    PARENT_DIR = sys._MEIPASS  # 生产环境
    LOG_DIR = os.path.expanduser("~/.linx-xiling/log/")
else:
    PARENT_DIR = os.path.abspath(os.path.join(
        os.path.dirname(__file__), os.pardir))  # 开发环境
    LOG_DIR = os.path.join(PARENT_DIR, 'log')

ASSIST_DIR = os.path.join(PARENT_DIR, 'assist')