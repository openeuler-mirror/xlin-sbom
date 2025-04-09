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

def get_file_relationships(file_list, package_id):
    """
    生成文件与包之间的关系列表。

    Args:
        file_list (list): 包含文件信息的列表，每个元素是一个字典，包含 "id" 键。
        package_id (str): 包的唯一标识符。

    Returns:
        list: 包含文件与包之间关系的列表，每个元素是一个字典，包含 "id"、"related_element" 和 "relationship_type" 键。
    """
    relationships = []
    for file in file_list:
        relationships.append({
            "id": package_id,
            "related_element": file['id'],
            "relationship_type": "CONTAINS"
        })
    return relationships


def get_rpm_relationships(packages, provides_relationships, disable_tqdm):
    """
    生成 RPM 包之间的依赖关系列表。

    Args:
        packages (list): 包含 RPM 包信息的列表，每个元素是一个字典，包含 "id" 和 "depends" 键。
        provides_relationships (list): 包含提供者关系信息的列表，每个元素是一个字典，包含 "id" 和 "provides" 键。
        disable_tqdm (bool): 是否禁用 tqdm 进度条。如果为 True，则不显示进度条。

    Returns:
        list: 包含 RPM 包之间依赖关系的列表，每个元素是一个字典，包含 "id"、"related_element" 和 "relationship_type" 键。
    """

    from tqdm import tqdm

    relationships = []
    # 根据 disable_tqdm 决定是否使用 tqdm
    package_iter = tqdm(packages, desc="处理包依赖关系", unit="包") if not disable_tqdm else packages

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
