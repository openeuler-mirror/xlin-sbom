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
    def __init__(self, name: str, version: str, release: str, arch: str, package_type: str, sha1: str):
        self.id = f"Package-{name}-{sha1[:12]}"
        self.name = name
        self.version = version
        self.release = release
        self.arch = arch
        self.package_type = package_type
        self.sha1 = sha1
        self.licenses = []
        self.category = "NOASSERTION"
        self.vulnerabilities = []
        self.files = []
        self.concluded_dependencies = []
        self.declared_dependencies = []

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

