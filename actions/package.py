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
    def __init__(self, name: str, version: str, release: str, arch: str,
                 package_type: str, checksum_algorithm: str, checksum_value: str):
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
        self.category = category

    def add_vulnerability(self, id: str, severity_type: str, severity_level: str, fixed: str) -> None:
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
        self.licenses.append(license)

    def add_file(self, file: dict) -> None:
        self.files.append(file)

    def add_files(self, files: list) -> None:
        self.files.extend(files)

    def add_concluded_dep(self, dependency: str) -> None:
        self.concluded_dependencies.append(dependency)

    def add_declared_dep(self, dependency: object) -> None:
        self.declared_dependencies.append(dependency)

    def set_source(self, source: str) -> None:
        self.source = source

    def add_supplier(self, supplier: dict) -> None:
        self.suppliers.append(supplier)

    def set_description(self, description: str) -> None:
        self.description = description
