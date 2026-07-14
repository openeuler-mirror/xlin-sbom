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

import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests

from actions import ASSIST_DIR
from actions.data_helper import read_data_from_json


CREATORS_FILE_PATH = os.path.join(ASSIST_DIR, "creators.json")
LICENSES_FILE_PATH = os.path.join(ASSIST_DIR, "licenses.json")
LICENSE_INDEX_FILE_PATH = os.path.join(ASSIST_DIR, "index.json")
REQUEST_TIMEOUT = 30
SIGNATURE_FILE_NAME = "signature.sig"
CERTIFICATE_FILE_NAME = "certification.pem"
PURL_TYPE_OSV_ECOSYSTEMS = {
    "cargo": "crates.io",
    "composer": "Packagist",
    "gem": "RubyGems",
    "golang": "Go",
    "hex": "Hex",
    "maven": "Maven",
    "npm": "npm",
    "nuget": "NuGet",
    "pub": "Pub",
    "pypi": "PyPI",
}

LICENSE_CATEGORY_DETAILS = [
    {
        "scancode_category": "CLA",
        "description": (
            "贡献者许可协议 (Contributor License Agreement - CLA)：该许可证描述和定义了软件项目持续开发和增强过程中"
            "接受贡献的规则。CLA 可能规定最终的软件贡献本身将如何被授权许可。"
        ),
    },
    {
        "scancode_category": "Commercial",
        "description": "商业许可证 (Commercial)：供应商和客户之间根据直接的商业许可协议提供的第三方专有软件。如无商业采购合同，贸然使用可能存在法律风险。",
    },
    {
        "scancode_category": "Copyleft",
        "description": (
            "著佐权许可证 (Copyleft)：采用'著佐权 (Copyleft)'许可的开源软件，授予公众不可撤销的复制和以相同或修改形式再分发作品的权限，"
            "但条件是所有此类再分发必须以便于进一步修改的形式提供作品，并使用相同的许可条款。著佐权许可要求与著佐权许可代码交互的代码"
            "也以相同方式获得许可（'传染性'）。"
        ),
    },
    {
        "scancode_category": "Copyleft Limited",
        "description": (
            "有限著佐权许可证 (Copyleft Limited)：要求再分发源代码（包括修改）并为软件作者提供归属声明的许可证。再分发源代码"
            "（包括与此许可下的代码链接的专有代码）的义务，根据特定许可的规则受到限制。"
        ),
    },
    {
        "scancode_category": "Free Restricted",
        "description": "受限免费许可证 (Free Restricted)：一种宽松式许可，但包含对软件使用或软件再分发的限制。",
    },
    {
        "scancode_category": "Non-Commercial",
        "description": "非商业许可证 (Non-Commercial)：第三方专有软件以禁止对相关软件进行任何商业用途的许可证形式提供。",
    },
    {
        "scancode_category": "Patent License",
        "description": "专利许可证 (Patent License)：一种适用于专利而非特定软件的许可证。可以与适用于软件组件的其他软件许可证结合使用。",
    },
    {
        "scancode_category": "Permissive",
        "description": (
            "宽松许可证 (Permissive)：在'非著佐权 (non-copyleft)'许可下提供的开源软件。这类许可证通常要求对所包含的开源代码进行归属声明，"
            "并可能包含其他义务。"
        ),
    },
    {
        "scancode_category": "Proprietary Free",
        "description": (
            "专有免费许可证 (Proprietary Free)：可能不需要商业许可但可能有特定条款和条件的专有免费软件，产品团队有义务遵守这些条款和条件。"
            "其中一些条款和条件随代码提供、或在代码中包含、或出现在可点击下载的许可证中。"
        ),
    },
    {
        "scancode_category": "Public Domain",
        "description": (
            "公共领域 (Public Domain)：没有明确义务即可使用的开源软件，但根据组织政策，必须随代码保留其许可证声明。该匹配可能适用于软件、"
            "网站上的代码示例、已发布的公共领域规范或其他类型的出版物。"
        ),
    },
    {
        "scancode_category": "Source-available",
        "description": (
            "源码可见 (Source-available)：源码可见软件是通过源代码分发模式发布的软件，其安排允许查看源代码，某些情况下也允许修改，"
            "但不一定满足称为开源软件的标准。"
        ),
    },
    {
        "scancode_category": "Unstated License",
        "description": "未声明许可证 (Unstated License)：具有版权声明但未明确声许可条款的第三方软件。常见示例包括来自出版物和网站的代码片段。",
    },
]


def convert_to_gbt(
    linx_sbom: Dict[str, Any],
    filename: str,
    created_time: str,
    package_type: str,
    scan_mode: str,
    ecosystem: Optional[str],
    config: Dict[str, Any],
    source_path: Optional[str] = None,
) -> Dict[str, Any]:
    """将 Linx SBOM 数据转换为 GB/T 47020-2026 JSON 结构。

    Args:
        linx_sbom (dict): Linx SBOM 数据。
        filename (str): 输出文件名基础值。
        created_time (str): UTC 创建时间，格式为 YYYY-MM-DDTHH:mm:ssZ。
        package_type (str): 当前扫描识别的软件包类型。
        scan_mode (str): 扫描模式，取值为 package、iso 或 docker。
        ecosystem (str | None): OSV 漏洞查询生态系统，组件缺少生态系统时作为兜底值。
        config (dict): 运行配置。
        source_path (str | None): 原始扫描对象路径，用于目标软件完整性计算。

    Returns:
        dict: GB/T 47020-2026 SBOM 数据。
    """

    packages = linx_sbom.get("packages_sbom", {}).get("packages", [])
    license_by_id = _build_license_id_name_map(linx_sbom)
    software_package, component_packages = _split_software_and_components(
        packages, scan_mode)
    software = _build_software(
        linx_sbom, filename, package_type, scan_mode,
        software_package, license_by_id, source_path)
    components = [
        _build_component(package, license_by_id)
        for package in component_packages
    ]
    dependencies = _build_dependencies(linx_sbom, software, components, scan_mode)
    licenses = _build_licenses(linx_sbom, software, components)
    vulnerability_subjects = _build_vulnerability_subjects(
        software_package, component_packages, software, components)
    vulnerabilities = query_gbt_vulnerabilities(
        vulnerability_subjects, ecosystem, config)
    creators = parse_creators(read_data_from_json(CREATORS_FILE_PATH))

    return {
        "software": software,
        "document": {
            "formatName": "SBOMDF",
            "formatVersion": "1.0",
            "listID": f"urn:uuid:{uuid.uuid4()}",
            "timestamp": created_time,
            "authors": creators.get("Organization", "Linx Software, Inc."),
            "createTools": build_create_tools(creators),
        },
        "components": components,
        "dependencies": dependencies,
        "licenses": licenses,
        "vulnerabilities": vulnerabilities,
        "integrity": {
            "signatureFile": SIGNATURE_FILE_NAME,
            "digitalCertificateFile": CERTIFICATE_FILE_NAME,
        },
    }


def parse_creators(creators: List[str]) -> Dict[str, str]:
    """解析 creators.json 中的创建者元数据。

    Args:
        creators (list[str]): creators.json 中的字符串列表。

    Returns:
        dict: 键为 Organization、Tool、Version 等元数据名称。
    """

    metadata = {}
    for creator in creators:
        if not isinstance(creator, str) or ":" not in creator:
            continue
        key, value = creator.split(":", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def build_create_tools(creators: Dict[str, str]) -> str:
    """根据 Tool 和 Version 构建国标 createTools 字段。

    Args:
        creators (dict): 创建者元数据。

    Returns:
        str: 创建工具名称和版本。
    """

    tool = creators.get("Tool", "XiLing SBOM Tool")
    version = creators.get("Version", "")
    if not version:
        logging.warning("creators.json 缺少 Version 字段，GBT createTools 将仅使用工具名称")
    return f"{tool}{version}" if version else tool


def query_gbt_vulnerabilities(
    packages: List[Dict[str, Any]],
    ecosystem: Optional[str],
    config: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """查询并转换国标安全漏洞信息。

    Args:
        packages (list[dict]): 待查询的软件或组件对象列表。
        ecosystem (str | None): OSV 漏洞查询生态系统兜底值。
        config (dict): 运行配置，包含 elastic_search。

    Returns:
        list[dict]: 国标 vulnerabilities 列表。
    """

    queries = _build_vulnerability_queries(packages, ecosystem)
    if not queries:
        return []

    es_config = config.get("elastic_search", {}) if config else {}
    try:
        raw_results = _query_es_vulnerabilities(queries, es_config)
    except Exception as exc:
        logging.warning(f"GBT 漏洞信息查询失败，将输出空漏洞列表: {exc}")
        return []

    vulnerabilities = []
    seen = set()
    for query, matched_vulnerabilities in zip(queries, raw_results):
        for vulnerability in matched_vulnerabilities:
            key = (
                vulnerability.get("vulnerabilityId"),
                vulnerability.get("affectedObject"),
            )
            if key in seen:
                continue
            seen.add(key)
            vulnerabilities.append(vulnerability)
    return vulnerabilities


def sign_gbt_sbom(sbom_path: str, signature_path: str, certificate_path: str) -> None:
    """使用 OpenSSL SM2/SM3 为国标 SBOM 文件生成签名和证书。

    Args:
        sbom_path (str): 已写入的国标 SBOM JSON 路径。
        signature_path (str): 签名文件输出路径。
        certificate_path (str): 数字证书输出路径。

    Returns:
        None

    Raises:
        RuntimeError: OpenSSL 不可用或签名失败。
    """

    try:
        with tempfile.TemporaryDirectory(prefix="linx_gbt_sign_") as temp_dir:
            private_key_path = os.path.join(temp_dir, "private.key")
            _run_openssl([
                "openssl", "genpkey", "-algorithm", "EC",
                "-pkeyopt", "ec_paramgen_curve:SM2",
                "-out", private_key_path,
            ])
            _run_openssl([
                "openssl", "req", "-new", "-x509",
                "-key", private_key_path,
                "-sm3", "-subj", "/CN=XiLing SBOM Tool",
                "-days", "3650",
                "-out", certificate_path,
            ])
            _run_openssl([
                "openssl", "dgst", "-sm3",
                "-sign", private_key_path,
                "-out", signature_path,
                sbom_path,
            ])
    except FileNotFoundError as exc:
        raise RuntimeError("未找到 OpenSSL，无法生成 GBT SBOM 签名文件") from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else str(exc)
        raise RuntimeError(f"OpenSSL SM2/SM3 签名失败: {message}") from exc


def _split_software_and_components(
    packages: List[Dict[str, Any]],
    scan_mode: str,
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    if scan_mode == "package":
        return (packages[0], packages[1:]) if packages else (None, [])
    return None, packages


def _build_software(
    linx_sbom: Dict[str, Any],
    filename: str,
    package_type: str,
    scan_mode: str,
    software_package: Optional[Dict[str, Any]],
    license_by_id: Dict[str, str],
    source_path: Optional[str],
) -> Dict[str, Any]:
    packages_header = linx_sbom.get("packages_sbom", {})
    if software_package:
        return {
            "softwareId": _no_assertion(software_package.get("id")),
            "softwareName": _no_assertion(software_package.get("name")),
            "softwareVersion": _no_assertion(software_package.get("version")),
            "integrity": _build_integrity(software_package.get("checksum", {})),
            "supplier": _build_supplier(software_package),
            "licenseName": _build_software_license_name(
                software_package, license_by_id),
        }

    return {
        "softwareId": _build_target_software_id(
            packages_header, filename, scan_mode),
        "softwareName": _resolve_target_software_name(
            packages_header, filename, scan_mode),
        "softwareVersion": _resolve_target_software_version(
            packages_header, package_type),
        "integrity": _build_target_integrity(packages_header, source_path),
        "supplier": {"supplierName": "NOASSERTION"},
        "licenseName": "NOASSERTION",
    }


def _build_component(
    package: Dict[str, Any],
    license_by_id: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "componentId": _no_assertion(package.get("id")),
        "componentName": _no_assertion(package.get("name")),
        "componentVersion": _no_assertion(package.get("version")),
        "supplier": _build_supplier(package),
        "licenseName": _resolve_package_license_names(package, license_by_id),
        "integrity": _build_integrity(package.get("checksum", {})),
    }


def _build_dependencies(
    linx_sbom: Dict[str, Any],
    software: Dict[str, Any],
    components: List[Dict[str, Any]],
    scan_mode: str,
) -> List[Dict[str, str]]:
    """构建国标 dependencies 列表。

    Args:
        linx_sbom (dict): Linx SBOM 数据。
        software (dict): 国标 software 对象。
        components (list[dict]): 国标 components 列表。
        scan_mode (str): 当前扫描模式。

    Returns:
        list[dict]: 国标 dependencies 关系列表。
    """

    relationships = []
    if scan_mode in ("iso", "docker"):
        software_id = _no_assertion(software.get("softwareId"))
        for component in components:
            _add_dependency(relationships, {
                "identityAId": software_id,
                "relationship": "contain",
                "identityBId": _no_assertion(component.get("componentId")),
            })

    for relationship in linx_sbom.get(
            "package_relationships_sbom", {}).get("package_relationships", []):
        _add_dependency(relationships, {
            "identityAId": _no_assertion(relationship.get("id")),
            "relationship": _map_relationship_type(
                relationship.get("relationship_type")),
            "identityBId": _no_assertion(relationship.get("related_element")),
        })
    return relationships


def _add_dependency(
    relationships: List[Dict[str, str]],
    relationship: Dict[str, str],
) -> None:
    """向关系列表追加去重后的国标 dependency。

    Args:
        relationships (list[dict]): 已构建的关系列表。
        relationship (dict): 待追加的关系。
    """

    if relationship not in relationships:
        relationships.append(relationship)


def _build_licenses(
    linx_sbom: Dict[str, Any],
    software: Dict[str, Any],
    components: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    license_names = []
    for license_info in linx_sbom.get("licenses_sbom", {}).get("licenses", []):
        _add_license_expression_names(license_names, license_info.get("name"))
    _add_license_expression_names(license_names, software.get("licenseName"))
    for component in components:
        for license_name in component.get("licenseName", []):
            _add_license_expression_names(license_names, license_name)

    return [
        _build_license(license_name)
        for license_name in license_names
    ]


def _build_license(license_name: str) -> Dict[str, Any]:
    license_rule = _find_license_rule(license_name)
    content_parts = []
    patent = False
    if license_rule:
        for obligation in license_rule.get("must", []):
            _add_license_name(content_parts, obligation.get("cn_name"))
        for permission in license_rule.get("can", []):
            _add_license_name(content_parts, permission.get("cn_name"))
            if permission.get("name") == "Patent Use":
                patent = True

    return {
        "licenseId": f"License-{hashlib.sha1(license_name.encode('utf-8')).hexdigest()[:12]}",
        "licenseName": license_name,
        "content": "，".join(content_parts) if content_parts else "未在许可证辅助数据中找到可自动提取的权利义务描述。",
        "scope": "Global",
        "patent": patent,
        "riskDescription": _get_license_risk_description(license_name),
    }


def _build_license_id_name_map(linx_sbom: Dict[str, Any]) -> Dict[str, str]:
    return {
        license_info.get("id"): license_info.get("name")
        for license_info in linx_sbom.get("licenses_sbom", {}).get("licenses", [])
        if license_info.get("id") and license_info.get("name")
    }


def _resolve_package_license_names(
    package: Dict[str, Any],
    license_by_id: Dict[str, str],
) -> List[str]:
    license_names = []
    for license_ref in package.get("licenses", []):
        _add_license_name(license_names, license_by_id.get(license_ref, license_ref))
    return license_names


def _build_software_license_name(
    package: Dict[str, Any],
    license_by_id: Dict[str, str],
) -> str:
    """构建国标 software.licenseName 字段。

    Args:
        package (dict): Linx 包对象。
        license_by_id (dict): Linx 许可证 ID 到名称的映射。

    Returns:
        str: 软件许可证表达式，缺失时返回 NOASSERTION。
    """

    license_names = _resolve_package_license_names(package, license_by_id)
    return " AND ".join(license_names) if license_names else "NOASSERTION"


def _build_supplier(package: Dict[str, Any]) -> Dict[str, str]:
    suppliers = package.get("suppliers") or []
    supplier_name = suppliers[0].get("name") if suppliers else None
    return {"supplierName": supplier_name or "NOASSERTION"}


def _build_integrity(checksum: Dict[str, Any]) -> Dict[str, str]:
    return {
        "hashAlg": _no_assertion(checksum.get("algorithm")),
        "messageDigest": _no_assertion(checksum.get("value")),
    }


def _build_target_integrity(
    packages_header: Dict[str, Any],
    source_path: Optional[str],
) -> Dict[str, str]:
    image_digest = (
        packages_header.get("image_digest")
        or packages_header.get("image_config_digest")
        or ""
    )
    if image_digest and image_digest != "NOASSERTION":
        algorithm, _, value = image_digest.partition(":")
        return {
            "hashAlg": algorithm.upper() if algorithm else "SHA256",
            "messageDigest": value or image_digest,
        }
    if source_path and os.path.isfile(source_path):
        return {
            "hashAlg": "SHA1",
            "messageDigest": _calculate_file_sha1(source_path),
        }
    return {
        "hashAlg": "NOASSERTION",
        "messageDigest": "NOASSERTION",
    }


def _resolve_target_software_name(
    packages_header: Dict[str, Any],
    filename: str,
    scan_mode: str,
) -> str:
    if scan_mode == "docker":
        return packages_header.get("image_name") or filename
    os_name = packages_header.get("os_name")
    if os_name and os_name != "NOASSERTION":
        return os_name
    return packages_header.get("scan_target") or filename


def _build_target_software_id(
    packages_header: Dict[str, Any],
    filename: str,
    scan_mode: str,
) -> str:
    """为 ISO 或 Docker 扫描目标生成可被 dependencies 引用的软件 ID。

    Args:
        packages_header (dict): Linx packages 清单头部。
        filename (str): 输出文件名基础值。
        scan_mode (str): 当前扫描模式。

    Returns:
        str: 稳定的软件标识。
    """

    target = (
        packages_header.get("image_name")
        or packages_header.get("scan_target")
        or filename
    )
    digest_source = f"{scan_mode}:{target}"
    digest = hashlib.sha1(digest_source.encode("utf-8")).hexdigest()[:12]
    return f"Software-{digest}"


def _resolve_target_software_version(
    packages_header: Dict[str, Any],
    package_type: str,
) -> str:
    os_version = packages_header.get("os_version")
    if os_version and os_version != "NOASSERTION":
        return os_version
    return package_type or "NOASSERTION"


def _build_vulnerability_queries(
    packages: List[Dict[str, Any]],
    ecosystem: Optional[str],
) -> List[Dict[str, str]]:
    queries = []
    seen = set()
    for package in packages:
        name = package.get("name")
        version = package.get("version")
        if not name or not version:
            continue
        query_ecosystem = package.get("ecosystem") or ecosystem
        if not query_ecosystem:
            continue
        key = (query_ecosystem, name, version, package.get("id"))
        if key in seen:
            continue
        seen.add(key)
        queries.append({
            "id": package.get("id") or f"{query_ecosystem}:{name}@{version}",
            "ecosystem": query_ecosystem,
            "name": name,
            "version": version,
        })
    return queries


def _build_vulnerability_subjects(
    software_package: Optional[Dict[str, Any]],
    component_packages: List[Dict[str, Any]],
    software: Dict[str, Any],
    components: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    """构建国标漏洞查询对象列表。

    Args:
        software_package (dict | None): 软件信息对应的 Linx 包。
        component_packages (list[dict]): 组件信息对应的 Linx 包列表。
        software (dict): 国标软件信息。
        components (list[dict]): 国标组件信息列表。

    Returns:
        list[dict]: 归一化后的 name/version 查询对象列表。
    """

    subjects = []
    if software_package:
        _add_vulnerability_subject(
            subjects,
            software_package.get("id"),
            software.get("softwareName"),
            software.get("softwareVersion"),
            _resolve_package_osv_ecosystem(software_package),
        )
    for package, component in zip(component_packages, components):
        _add_vulnerability_subject(
            subjects,
            component.get("componentId") or package.get("id"),
            component.get("componentName"),
            component.get("componentVersion"),
            _resolve_package_osv_ecosystem(package),
        )
    return subjects


def _resolve_package_osv_ecosystem(package: Dict[str, Any]) -> Optional[str]:
    """根据 Linx 包类型推断 OSV 生态系统。

    Args:
        package (dict): Linx 包对象。

    Returns:
        str | None: 可用于 OSV 查询的生态系统名称，无法推断时返回 None。
    """

    ecosystem = package.get("ecosystem")
    if ecosystem:
        return str(ecosystem)
    package_type = str(package.get("package_type") or "").lower()
    return PURL_TYPE_OSV_ECOSYSTEMS.get(package_type)


def _add_vulnerability_subject(
    subjects: List[Dict[str, str]],
    subject_id: Any,
    name: Any,
    version: Any,
    ecosystem: Optional[str] = None,
) -> None:
    """向漏洞查询对象列表追加有效的软件或组件标识。

    Args:
        subjects (list[dict]): 待追加的查询对象列表。
        subject_id (Any): 受影响对象 ID。
        name (Any): 软件或组件名称。
        version (Any): 软件或组件版本。
        ecosystem (str | None): 组件自身的 OSV 生态系统。
    """

    if not subject_id or not name or not version:
        return
    subject_id = str(subject_id)
    name = str(name)
    version = str(version)
    if (
            subject_id == "NOASSERTION"
            or name == "NOASSERTION"
            or version == "NOASSERTION"):
        return
    subject = {"id": subject_id, "name": name, "version": version}
    if ecosystem:
        subject["ecosystem"] = ecosystem
    if subject not in subjects:
        subjects.append(subject)


def _query_es_vulnerabilities(
    queries: List[Dict[str, str]],
    es_config: Dict[str, Any],
) -> List[List[Dict[str, Any]]]:
    hosts = es_config.get("hosts") or []
    index_name = es_config.get("index_name")
    if not hosts or not index_name:
        raise ValueError("elastic_search.hosts 或 elastic_search.index_name 未配置")

    headers = {"Content-Type": "application/x-ndjson"}
    api_key = es_config.get("api_key")
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    body = _build_msearch_body(queries, index_name)
    response = requests.post(
        f"{hosts[0].rstrip('/')}/_msearch",
        data=body.encode("utf-8"),
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        verify=_resolve_es_verify(es_config),
    )
    response.raise_for_status()
    return _parse_msearch_response(queries, response.json())


def _resolve_es_verify(es_config: Dict[str, Any]) -> Any:
    """解析 Elasticsearch HTTPS 证书校验参数。

    Args:
        es_config (dict): Elasticsearch 连接配置。

    Returns:
        bool | str: 关闭校验时返回 False，指定 CA 时返回证书路径，
            其他情况返回 True。
    """

    if not es_config.get("verify_certs", True):
        return False
    ca_certs = es_config.get("ca_certs", "")
    if isinstance(ca_certs, str) and ca_certs.strip():
        return ca_certs.strip()
    return True


def _build_msearch_body(
    queries: List[Dict[str, str]],
    index_name: str,
) -> str:
    lines = []
    for query in queries:
        lines.append({"index": index_name})
        lines.append({
            "query": {
                "nested": {
                    "path": "affected",
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"affected.package.ecosystem": query["ecosystem"]}},
                                {"term": {"affected.package.name": query["name"]}},
                            ]
                        }
                    },
                }
            },
            "size": 1000,
        })
    return "\n".join(_json_dumps(line) for line in lines) + "\n"


def _parse_msearch_response(
    queries: List[Dict[str, str]],
    payload: Dict[str, Any],
) -> List[List[Dict[str, Any]]]:
    results = []
    for query, response in zip(queries, payload.get("responses", [])):
        vulnerabilities = []
        hits = response.get("hits", {}).get("hits", [])
        for hit in hits:
            source = hit.get("_source", {})
            vulnerabilities.extend(_match_vulnerability(query, source))
        results.append(vulnerabilities)
    return results


def _match_vulnerability(
    query: Dict[str, str],
    source: Dict[str, Any],
) -> List[Dict[str, Any]]:
    matched = []
    for affected in source.get("affected", []):
        package = affected.get("package", {})
        versions = affected.get("versions", [])
        if package.get("ecosystem") != query["ecosystem"]:
            continue
        if package.get("name") != query["name"]:
            continue
        if query["version"] not in versions:
            continue

        fixed = _extract_fixed_version(affected)
        if fixed:
            repair_method = "更新组件版本"
            repair_description = f"更新组件版本至{fixed}"
        else:
            repair_method = "暂无"
            repair_description = "暂无"
        matched.append({
            "vulnerabilityId": source.get("id"),
            "vulnerabilityName": source.get("id"),
            "affectedObject": query.get(
                "id", f"{query['ecosystem']}:{query['name']}@{query['version']}"),
            "otherID": source.get("aliases", []),
            "repairMethod": repair_method,
            "repairMethodDescription": repair_description,
        })
    return matched


def _extract_fixed_version(affected: Dict[str, Any]) -> str:
    for version_range in affected.get("ranges", []):
        for event in version_range.get("events", []):
            if event.get("fixed"):
                return event.get("fixed")
    return ""


def _find_license_rule(license_name: str) -> Optional[Dict[str, Any]]:
    try:
        licenses = read_data_from_json(LICENSES_FILE_PATH)
    except Exception:
        return None

    normalized = license_name.lower()
    for license_rule in licenses:
        names = [license_rule.get("spdx_name", "")]
        names.extend(license_rule.get("alt_names", []))
        if any(normalized == str(name).lower() for name in names):
            return license_rule
    return None


def _get_license_risk_description(license_name: str) -> str:
    category = _get_license_category(license_name)
    for item in LICENSE_CATEGORY_DETAILS:
        if item.get("scancode_category") == category:
            return item.get("description")
    return "未在许可证分类辅助数据中找到对应风险分类，请结合许可证原文进行人工确认。"


def _get_license_category(license_name: str) -> str:
    try:
        index = read_data_from_json(LICENSE_INDEX_FILE_PATH)
    except Exception:
        return "Unknown"

    normalized = license_name.lower()
    for item in index:
        keys = [
            item.get("license_key", ""),
            item.get("spdx_license_key", ""),
        ]
        keys.extend(item.get("other_spdx_license_keys", []))
        if any(normalized == str(key).lower() for key in keys):
            return item.get("category", "Unknown")
    return "Unknown"


def _map_relationship_type(relationship_type: str) -> str:
    return {
        "DEPENDS_ON": "dependsOn",
        "CONTAINS": "contain",
    }.get(relationship_type, "other")


def _calculate_file_sha1(file_path: str) -> str:
    sha1 = hashlib.sha1()
    with open(file_path, "rb") as source:
        chunk = source.read(1024 * 1024)
        while chunk:
            sha1.update(chunk)
            chunk = source.read(1024 * 1024)
    return sha1.hexdigest()


def _add_license_name(license_names: List[str], value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            _add_license_name(license_names, item)
        return
    if not value:
        return
    license_name = str(value)
    if license_name == "NOASSERTION":
        return
    if license_name not in license_names:
        license_names.append(license_name)


def _add_license_expression_names(license_names: List[str], value: Any) -> None:
    """拆分许可证表达式并追加到去重列表。

    Args:
        license_names (list[str]): 待追加的许可证名称列表。
        value (Any): 许可证名称、组合表达式或列表。
    """

    if isinstance(value, list):
        for item in value:
            _add_license_expression_names(license_names, item)
        return
    if not value:
        return
    for license_name in re.split(r"\s+AND\s+", str(value), flags=re.IGNORECASE):
        _add_license_name(license_names, license_name.strip(" ()"))


def _no_assertion(value: Any) -> str:
    return "NOASSERTION" if value is None or value == "" else str(value)


def _run_openssl(command: List[str]) -> None:
    subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def _json_dumps(value: Dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False)
