# Copyright (c) 2025 Linx Software, Inc.
#
# xlin-sbom-analysis tool is licensed under Mulan PSL v2.

# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
# http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

class Package:
    """描述扫描得到的软件包及其 SBOM 关联数据。"""

    def __init__(self, name: str, version: str, release: str, arch: str,
                 package_type: str, checksum_algorithm: str, checksum_value: str):
        """初始化软件包对象。

        Args:
            name (str): 软件包名称。
            version (str): 软件包版本。
            release (str): RPM release 或等价发布字段。
            arch (str): 软件包架构。
            package_type (str): 包类型，例如 rpm、deb、source。
            checksum_algorithm (str): 校验和算法。
            checksum_value (str): 校验和值。
        """

        self.id = f"Package-{name}-{checksum_value[:12]}"
        self.name = name
        self.version = version
        self.release = release
        self.arch = arch
        self.package_type = package_type
        self.checksum_algorithm = checksum_algorithm
        self.checksum_value = checksum_value
        self.licenses = []
        self.category = "NOASSERTION"
        self.vulnerabilities = []
        self.files = []
        self.concluded_dependencies = []
        self.declared_dependencies = []
        self.source = "NOASSERTION"
        self.suppliers = []
        self.description = "NOASSERTION"

    def set_category(self, category: str) -> None:
        """设置软件包分类。

        Args:
            category (str): 软件包分类。
        """

        self.category = category

    def add_vulnerability(self, id: str, severity_type: str, severity_level: str, fixed: str) -> None:
        """追加漏洞信息。

        Args:
            id (str): 漏洞编号。
            severity_type (str): 严重性类型。
            severity_level (str): 严重性级别。
            fixed (str): 修复版本或修复说明。
        """

        if any(vuln['id'] == id for vuln in self.vulnerabilities):
            return

        vulnerability = {
            "id": id,
            "severity_type": severity_type,
            "severity_level": severity_level,
            "fixed": fixed
        }
        self.vulnerabilities.append(vulnerability)

    def add_license(self, license: str) -> None:
        """追加许可证引用。

        Args:
            license (str): 许可证 ID 或名称。
        """

        self.licenses.append(license)

    def add_file(self, file: dict) -> None:
        """追加包内文件。

        Args:
            file (dict): Linx 文件对象。
        """

        self.files.append(file)

    def add_files(self, files: list) -> None:
        """批量追加包内文件。

        Args:
            files (list): Linx 文件对象列表。
        """

        self.files.extend(files)

    def add_declared_dep(self, dependency: str) -> None:
        """追加声明依赖。

        Args:
            dependency (str): 依赖名称或表达式。
        """

        self.declared_dependencies.append(dependency)

    def add_concluded_dep(self, dependency: object) -> None:
        """追加解析后的依赖对象。

        Args:
            dependency (object): 已匹配到的依赖包对象。
        """

        self.concluded_dependencies.append(dependency)

    def set_source(self, source: str) -> None:
        """设置源码包或来源包信息。

        Args:
            source (str): 来源包名称。
        """

        self.source = source

    def add_supplier(self, supplier: dict) -> None:
        """追加供应商信息。

        Args:
            supplier (dict): Linx supplier 对象。
        """

        self.suppliers.append(supplier)

    def set_description(self, description: str) -> None:
        """设置软件包描述。

        Args:
            description (str): 描述文本。
        """

        self.description = description
    
    def get_file_relationships(self) -> list:
        """生成包与文件之间的包含关系。

        Returns:
            list: Linx file_relationships 列表。
        """

        relationships = []
        for file in self.files:
            relationships.append({
                "id": self.id,
                "related_element": file['id'],
                "relationship_type": "CONTAINS"
            })
        return relationships

    def get_json(self) -> dict:
        """转换为 Linx package JSON 对象。

        Returns:
            dict: Linx packages 列表中的单个 package 对象。
        """

        full_version = f"{self.version}-{self.release}" if self.release else self.version
        depends = [
            dep.name for dep in self.concluded_dependencies] if self.concluded_dependencies else self.declared_dependencies
        return {
            "id": self.id,
            "name": self.name,
            "version": full_version,
            "architecture": self.arch,
            "package_type": self.package_type,
            "depends": depends,
            "source": self.source,
            "licenses": self.licenses,
            "suppliers": self.suppliers,
            "description": self.description,
            "checksum": {
                "value": self.checksum_value,
                "algorithm": self.checksum_algorithm
            }
        }
