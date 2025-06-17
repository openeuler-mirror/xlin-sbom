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

from typing import List, Dict, Optional, Tuple, Any

def extract_originator_name(
    homepage: str, 
    originators: List[Dict[str, Any]]
) -> Tuple[Optional[str], bool, List[Dict[str, Any]]]:
    """
    从给定的主页 URL 和一组原始作者信息中提取原始作者的名称及其是否为组织。

    Args:
        homepage (str): 原始作者的主页 URL。
        originators (list): 包含原始作者信息的列表，每个元素是一个字典，包含 "homepage"、"name"、"is_organization" 和 "file_analyzed" 键。

    Returns:
        tuple: 包含三个元素的元组：
            - name (str or None): 原始作者的名称。如果未找到匹配项，则为 `None`。
            - is_organization (bool): 是否为组织。
            - originators (list): 更新后的原始作者信息列表。
    """

    if not homepage:
        return homepage, False, originators

    # 尝试从originators中找到与homepage匹配的项
    matched_originator = next((originator for originator in originators
                               if originator.get('homepage') == homepage), None)

    if matched_originator:
        # 如果找到匹配项，返回其名称、是否为组织及原originators列表
        name = matched_originator.get('name')
        is_organization = matched_originator.get('is_organization')
        return name, is_organization, originators
    else:
        # 未找到匹配时，创建新originator条目并添加至列表
        new_originator = {
            "homepage": homepage,
            "name": None,
            "is_organization": False,
            "file_analyzed": False
        }
        originators.append(new_originator)

        return None, False, originators
