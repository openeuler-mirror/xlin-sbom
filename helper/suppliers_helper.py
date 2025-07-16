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

from helper import ASSIST_DIR
from helper.data_helper import read_data_from_json
from typing import Any, Dict, List, Optional, Union
import os


suppliers_file_path = os.path.join(ASSIST_DIR, 'suppliers.json')
supplier_list = read_data_from_json(suppliers_file_path)
RPM_SUPPLIERS = [
    supplier for supplier in supplier_list if supplier.get('type') == 'rpm']


def get_suppliers(
    direct_supplier: str,
    homepage: Optional[str],
    originator_name: Optional[str],
    supplier_dicts: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    根据提供的参数获取供应商信息并分类。

    Args:
        direct_supplier (str): 直接供应商名称。
        homepage (str): 软件包主页链接。
        originator_name (str): 软件包原始作者名称。
        supplier_dicts (list): 供应商字典列表。

    Returns:
        list: 供应商信息列表。
    """

    # 初始化供应商列表
    suppliers = []
    current_tier = 0

    def _contains_keyword(string: str, keywords: List[str]) -> bool:
        """检查字符串是否包含任意一个关键词。"""
        return any(keyword in string for keyword in keywords)

    def _add_supplier(name: str, link: Optional[str], tier_increment: int = 1) -> None:
        """添加供应商信息到列表中。"""
        nonlocal current_tier
        current_tier += tier_increment
        suppliers.append({
            "name": name,
            "tier": current_tier,
            "link": link
        })

    for supplier in supplier_dicts:
        supplier_name = direct_supplier
        supplier_link = None
        if _contains_keyword(direct_supplier, supplier.get('keywords')):
            supplier_name = supplier.get('name')
            supplier_link = supplier.get('url')
            break
    if supplier_link:
        _add_supplier(supplier_name, supplier_link)
    if homepage:
        _add_supplier(originator_name, homepage)


    # 返回供应商列表和软件包类型
    return suppliers
