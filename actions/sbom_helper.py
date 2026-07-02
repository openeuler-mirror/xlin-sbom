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
from typing import Any, Dict, List, Optional

from actions import ASSIST_DIR
from actions.data_helper import read_data_from_json


CREATORS_FILE_PATH = os.path.join(ASSIST_DIR, "creators.json")


def build_sbom_header(
    sbom_data: List[Dict[str, Any]],
    data_name: str,
    scan_target: str,
    created_time: str,
    os_name: Optional[str] = None,
    os_version: Optional[str] = None,
    os_arch: Optional[str] = None,
) -> Dict[str, Any]:
    """为 SBOM 数据构建统一头部。

    Args:
        sbom_data (list[dict]): 当前清单类型的数据列表。
        data_name (str): 数据类型名称，例如 packages、files 或 licenses。
        scan_target (str): 当前扫描目标名称或地址。
        created_time (str): SBOM 创建时间。
        os_name (str | None): ISO 扫描时识别到的操作系统名称。
        os_version (str | None): ISO 扫描时识别到的操作系统版本。
        os_arch (str | None): ISO 扫描时识别到的操作系统架构。

    Returns:
        dict: 包含 creation_info 和清单数据的 SBOM 片段。
    """

    if os_name is not None or os_version is not None or os_arch is not None:
        return {
            "scan_target": scan_target or "NOASSERTION",
            "os_name": os_name or "NOASSERTION",
            "os_version": os_version or "NOASSERTION",
            "os_arch": os_arch or "NOASSERTION",
            "creation_info": {
                "creators": read_data_from_json(CREATORS_FILE_PATH),
                "created": created_time,
            },
            data_name: sbom_data,
        }

    return {
        "scan_target": scan_target or "NOASSERTION",
        "creation_info": {
            "creators": read_data_from_json(CREATORS_FILE_PATH),
            "created": created_time,
        },
        data_name: sbom_data,
    }
