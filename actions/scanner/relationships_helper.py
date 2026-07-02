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


from typing import List, Dict, Any
from tqdm import tqdm
import logging
import re


def get_deb_relationships(packages, disable_tqdm):
    relationships = []

    # 将软件包名称映射到ID
    name_to_id = {info['name']: info['id'] for info in packages}

    # 根据 disable_tqdm 决定是否使用 tqdm
    package_iter = tqdm(packages, desc="处理包依赖关系",
                        unit="包") if not disable_tqdm else packages

    # 遍历每个软件包，获取依赖关系
    for package in package_iter:
        processed_deps = []
        package_id = package['id']

        # 遍历当前软件包的所有依赖字符串
        for dependency_str in package.get('depends', []):
            # 如果依赖项包含分支符号'|'，则分割处理
            deps_to_check = [
                dependency_str] if "|" not in dependency_str else _split_package_choice(dependency_str)

            # 遍历待检查的依赖项
            for dep in deps_to_check:
                if dep not in processed_deps:
                    processed_deps.append(dep)

                    # 去除依赖项中的版本限定符
                    stripped_dep = _strip_version_specifier(dep)

                    # 根据依赖项名称查找对应的ID
                    dep_id = name_to_id.get(stripped_dep)
                    if not dep_id:
                        logging.warning(
                            f"无法找到包 {package_id} 的依赖项 {stripped_dep}")
                    # 确保不记录软件包对自己的依赖，然后添加依赖关系到列表
                    elif package_id != dep_id:
                        relationships.append({
                            "id": package_id,
                            "related_element": dep_id,
                            "relationship_type": "DEPENDS_ON"
                        })

    return relationships

def get_rpm_relationships(
    packages: List[Dict[str, Any]],
    provides_relationships: List[Dict[str, Any]],
    disable_tqdm: bool
) -> List[Dict[str, Any]]:
    """
    生成 RPM 包之间的依赖关系列表。

    Args:
        packages (list): 包含 RPM 包信息的列表，每个元素是一个字典，包含 "id" 和 "depends" 键。
        provides_relationships (list): 包含提供者关系信息的列表，每个元素是一个字典，包含 "id" 和 "provides" 键。
        disable_tqdm (bool): 是否禁用 tqdm 进度条。如果为 True，则不显示进度条。

    Returns:
        list: 包含 RPM 包之间依赖关系的列表，每个元素是一个字典，包含 "id"、"related_element" 和 "relationship_type" 键。
    """

    relationships = []
    # 根据 disable_tqdm 决定是否使用 tqdm
    package_iter = tqdm(packages, desc="处理包依赖关系",
                        unit="包") if not disable_tqdm else packages

    for package in package_iter:
        added_relationships = []
        for dep in package.get('depends', []):
            for provide_relationship in provides_relationships:
                provides = provide_relationship.get("provides", [])
                related_element = provide_relationship.get('id')
                if dep in provides and related_element not in added_relationships and related_element != package.get('id'):
                    added_relationships.append(related_element)
                    relationships.append({
                        "id": package.get('id'),
                        "related_element": related_element,
                        "relationship_type": "DEPENDS_ON"
                    })

    if not disable_tqdm:
        package_iter.close()  # 确保 tqdm 资源被正确关闭

    return relationships


def _strip_version_specifier(s):
    """
    从字符串中移除版本指定符，返回纯净的包名或依赖名称。

    Args:
        s (str): 原始字符串，可能包含版本号及比较符，如">=1.2.3"或"package_name:any".

    Returns:
        str: 移除了所有版本指定符及相关的任何版本信息后的纯净字符串。
    """
    return re.split(r'[(<>]', s.strip())[0].replace(":any", "").strip()


def _split_package_choice(s):
    """
    分割包含多个选择项的包名或依赖定义字符串，并移除每个选项中的版本指定符。

    Args:
        s (str): 用"|"分隔的包名或依赖定义字符串。

    Returns:
        list[str]: 一个列表，包含各个选项经过 `_strip_version_specifier` 处理后的纯净包名或版本号。
    """
    return [_strip_version_specifier(field.strip()) for field in s.split("|") if field.strip()]
