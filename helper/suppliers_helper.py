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
from helper.json_helper import read_data_from_json
import os


suppliers_file_path = os.path.join(ASSIST_DIR, 'suppliers.json')
supplier_list = read_data_from_json(suppliers_file_path)
RPM_SUPPLIERS = [
    supplier for supplier in supplier_list if supplier.get('type') == 'rpm']


def get_suppliers(package_name, package_version, direct_supplier, homepage, originator_name, supplier_dicts, category_dict):
    """
    根据提供的参数获取供应商信息并分类。

    Args:
        package_name (str): 软件包名称。
        package_version (str): 软件包版本。
        direct_supplier (str): 直接供应商名称。
        homepage (str): 软件包主页链接。
        originator_name (str): 软件包原始作者名称。
        supplier_dicts (list): 供应商字典列表。
        category_dict (dict): 分类字典。

    Returns:
        tuple: 包含两个元素的元组：
            - suppliers (list): 供应商信息列表。
            - category (str): 软件包类型（'self_developed'、'modified' 或 'third_party'）。
    """

    # 初始化供应商列表
    suppliers = []
    current_tier = 0

    # 获取关键字段
    keywords = ['linx', 'vlx']
    filter_words = ["<insert the upstream URL, if relevant>"]

    def _contains_keyword(string, keywords):
        """检查字符串是否包含任意一个关键词。"""
        return any(keyword in string for keyword in keywords)

    def _add_supplier(name, link, tire_increment=1):
        """添加供应商信息到列表中。"""
        nonlocal current_tier
        current_tier += tire_increment
        suppliers.append({
            "name": name,
            "tier": current_tier,
            "link": link
        })

    def _add_first_party_supplier():
        """添加第一方供应商。"""
        _add_supplier("Linx Software", "https://www.linx-info.com/")

    def _add_third_party_suppliers():
        """添加第三方供应商。"""
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

    # 如果提供了category_dict，则根据字典中的条目确定软件包类别
    if category_dict:
        category = category_dict.get(package_name, "third_party")
        if category == "self_developed":
            _add_first_party_supplier()
        elif category == "modified":
            _add_first_party_supplier()
            _add_third_party_suppliers()
        else:
            _add_third_party_suppliers()

    # 如果没有提供category_dict，则根据关键字和其他条件判断
    else:
        if _contains_keyword(package_name.lower(), keywords) or (_contains_keyword(direct_supplier.lower(), keywords) and (not homepage or homepage in filter_words or _contains_keyword(homepage, keywords))):
            _add_first_party_supplier()
            category = "self_developed"
        elif _contains_keyword(package_version.lower(), keywords) or _contains_keyword(direct_supplier.lower(), keywords):
            _add_first_party_supplier()
            _add_third_party_suppliers()
            category = "modified"
        else:
            _add_third_party_suppliers()
            category = "third_party"

    # 返回供应商列表和软件包类型
    return suppliers, category
