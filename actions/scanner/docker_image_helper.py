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

from dataclasses import dataclass
from typing import Any, BinaryIO, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile

import requests

from actions import ASSIST_DIR
from actions.data_helper import read_data_from_json, remove_duplicates
from actions.licenses_helper import _extract_deb_license_list, rpm_licenses_scanner
from actions.package import Package
from actions.sbom_helper import build_sbom_header
from actions.scanner.originators_helper import extract_originator_name
from actions.scanner.relationships_helper import get_deb_relationships, get_rpm_relationships
from actions.scanner.suppliers_helper import DEB_SUPPLIERS, RPM_SUPPLIERS, get_suppliers


REQUEST_TIMEOUT = 30
DOCKERHUB_AUTH_URL = "https://auth.docker.io/token"
DOCKERHUB_REGISTRY_URL = "https://registry-1.docker.io"
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json,"
    "application/vnd.docker.distribution.manifest.list.v2+json,"
    "application/vnd.oci.image.manifest.v1+json,"
    "application/vnd.docker.distribution.manifest.v2+json"
)
BLOB_CHUNK_SIZE = 1024 * 1024


@dataclass
class DockerImageInfo:
    """记录 Docker 镜像解析过程中获得的元数据。"""

    target: str
    display_name: str
    image_digest: str
    config_digest: str
    os_name: Optional[str]
    os_version: Optional[str]
    os_arch: Optional[str]


def scan_docker_image(
    image_input: str,
    created_time: str,
    platform: str,
    disable_tqdm: bool,
) -> Tuple[Dict[str, Any], str, str]:
    """扫描 Docker 镜像并生成 Linx SBOM 数据。

    Args:
        image_input (str): Docker Hub 镜像名或离线镜像 tar 路径。
        created_time (str): SBOM 创建时间。
        platform (str): 多架构镜像的平台选择，例如 linux/amd64。
        disable_tqdm (bool): 是否禁用进度条，预留给关系计算逻辑使用。

    Returns:
        tuple: 包含 Linx SBOM、SPDX 默认包类型和输出文件名。

    Raises:
        ValueError: 镜像输入无法解析或镜像内未发现支持的包系统。
    """

    selected_platform = _parse_platform(platform)
    output_name = build_docker_output_name(image_input)
    with tempfile.TemporaryDirectory(prefix="linx_docker_") as temp_dir:
        rootfs_dir = os.path.join(temp_dir, "rootfs")
        os.makedirs(rootfs_dir, exist_ok=True)
        if _is_local_image_archive(image_input):
            image_info = _load_local_archive(image_input, rootfs_dir, selected_platform)
        else:
            image_info = _pull_dockerhub_image(
                image_input, rootfs_dir, selected_platform, temp_dir)

        image_info.os_name, image_info.os_version = _read_os_release(rootfs_dir)
        if not image_info.os_arch:
            image_info.os_arch = selected_platform[1]

        if _has_dpkg_database(rootfs_dir):
            logging.info("Docker 镜像中侦测到 DEB 包系统")
            linx_sbom = _scan_dpkg_rootfs(
                rootfs_dir, image_info, created_time, disable_tqdm)
            return linx_sbom, "docker", output_name

        if _has_rpm_database(rootfs_dir):
            logging.info("Docker 镜像中侦测到 RPM 包系统")
            linx_sbom = _scan_rpm_rootfs(
                rootfs_dir, image_info, created_time, disable_tqdm)
            return linx_sbom, "docker", output_name

        raise ValueError("Docker 镜像内未发现 dpkg 或 RPM 包数据库，无法识别可扫描的软件包系统。")


def build_docker_output_name(image_input: str) -> str:
    """构建 Docker 镜像扫描输出目录名称。

    Args:
        image_input (str): Docker Hub 镜像名或离线镜像路径。

    Returns:
        str: 适合用作输出目录和文件名前缀的名称。
    """

    if os.path.isfile(image_input):
        base_name = os.path.splitext(os.path.basename(image_input))[0]
    else:
        base_name = image_input
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", base_name).strip("._")
    return normalized or "docker_image"


def _parse_platform(platform: str) -> Tuple[str, str, Optional[str]]:
    """解析 Docker 平台字符串。

    Args:
        platform (str): 平台字符串，例如 linux/amd64 或 linux/arm64/v8。

    Returns:
        tuple: os、architecture、variant。

    Raises:
        ValueError: 平台字符串格式不合法。
    """

    fields = [field for field in platform.split("/") if field]
    if len(fields) not in (2, 3):
        raise ValueError("Docker 平台参数格式无效，应为 os/arch 或 os/arch/variant，例如 linux/amd64。")
    return fields[0], fields[1], fields[2] if len(fields) == 3 else None


def _is_local_image_archive(image_input: str) -> bool:
    """判断输入是否为本地离线镜像文件。

    Args:
        image_input (str): 用户输入的镜像参数。

    Returns:
        bool: True 表示按本地 tar 解析，False 表示按 Docker Hub 镜像名解析。

    Raises:
        ValueError: 用户输入看起来是本地 tar 路径但文件不存在。
    """

    if os.path.isfile(image_input):
        return True
    if image_input.lower().endswith(".tar"):
        raise ValueError(f"离线 Docker 镜像文件不存在: {image_input}")
    return False


def _load_local_archive(
    image_path: str,
    rootfs_dir: str,
    platform: Tuple[str, str, Optional[str]],
) -> DockerImageInfo:
    """解析本地 Docker/OCI 镜像归档并展开最终文件系统。

    Args:
        image_path (str): 离线镜像 tar 路径。
        rootfs_dir (str): 最终文件系统展开目录。
        platform (tuple): 目标平台。

    Returns:
        DockerImageInfo: 解析到的镜像元数据。
    """

    try:
        with tarfile.open(image_path, "r:*") as archive:
            names = set(archive.getnames())
            if "manifest.json" in names:
                return _load_docker_archive_manifest(
                    archive, image_path, rootfs_dir, platform)
            if "index.json" in names:
                return _load_oci_archive_manifest(
                    archive, image_path, rootfs_dir, platform)
    except tarfile.TarError as exc:
        raise ValueError(f"离线 Docker 镜像 tar 文件无法解析: {exc}") from exc

    raise ValueError("离线 Docker 镜像结构无法识别，未找到 manifest.json 或 index.json。")


def _load_docker_archive_manifest(
    archive: tarfile.TarFile,
    image_path: str,
    rootfs_dir: str,
    platform: Tuple[str, str, Optional[str]],
) -> DockerImageInfo:
    """解析 Docker save 格式 manifest 并展开层。"""

    manifest = _read_json_member(archive, "manifest.json")
    if not manifest:
        raise ValueError("离线 Docker 镜像 manifest.json 为空。")
    selected = manifest[0]
    config_name = selected.get("Config")
    layers = selected.get("Layers") or []
    if not config_name or not layers:
        raise ValueError("离线 Docker 镜像 manifest.json 缺少 Config 或 Layers 字段。")

    config = _read_json_member(archive, config_name)
    _ensure_config_matches_platform(config, platform)
    for layer_name in layers:
        _apply_archive_layer(archive, layer_name, rootfs_dir)

    repo_tags = selected.get("RepoTags") or []
    return DockerImageInfo(
        target=image_path,
        display_name=repo_tags[0] if repo_tags else os.path.basename(image_path),
        image_digest=_digest_for_text(json.dumps(selected, sort_keys=True)),
        config_digest=_digest_from_blob_path(config_name),
        os_name=config.get("os"),
        os_version=None,
        os_arch=config.get("architecture"),
    )


def _load_oci_archive_manifest(
    archive: tarfile.TarFile,
    image_path: str,
    rootfs_dir: str,
    platform: Tuple[str, str, Optional[str]],
) -> DockerImageInfo:
    """解析 OCI archive 格式 index/manifest 并展开层。"""

    index = _read_json_member(archive, "index.json")
    descriptor = _select_manifest_descriptor(index, platform)
    manifest_path = _blob_path_from_digest(descriptor.get("digest", ""))
    manifest = _read_json_member(archive, manifest_path)
    config_descriptor = manifest.get("config") or {}
    config_path = _blob_path_from_digest(config_descriptor.get("digest", ""))
    config = _read_json_member(archive, config_path)
    _ensure_config_matches_platform(config, platform)

    for layer in manifest.get("layers", []):
        _apply_archive_layer(
            archive, _blob_path_from_digest(layer.get("digest", "")), rootfs_dir)

    annotations = descriptor.get("annotations") or {}
    return DockerImageInfo(
        target=image_path,
        display_name=annotations.get(
            "io.containerd.image.name",
            annotations.get("org.opencontainers.image.ref.name",
                            os.path.basename(image_path))),
        image_digest=descriptor.get("digest", ""),
        config_digest=config_descriptor.get("digest", ""),
        os_name=config.get("os"),
        os_version=None,
        os_arch=config.get("architecture"),
    )


def _pull_dockerhub_image(
    image_ref: str,
    rootfs_dir: str,
    platform: Tuple[str, str, Optional[str]],
    temp_dir: str,
) -> DockerImageInfo:
    """从 Docker Hub 拉取公共镜像并展开最终文件系统。"""

    repository, reference, display_name = _parse_dockerhub_reference(image_ref)
    token = _fetch_dockerhub_token(repository)
    manifest, manifest_digest = _fetch_manifest(repository, reference, token)
    media_type = manifest.get("mediaType", "")
    if media_type.endswith("manifest.list.v2+json") or media_type.endswith("image.index.v1+json"):
        descriptor = _select_manifest_descriptor(manifest, platform)
        manifest, manifest_digest = _fetch_manifest(
            repository, descriptor.get("digest", ""), token)

    config_descriptor = manifest.get("config") or {}
    config = _fetch_blob_json(repository, config_descriptor.get("digest", ""), token)
    _ensure_config_matches_platform(config, platform)
    for index, layer in enumerate(manifest.get("layers", [])):
        layer_path = os.path.join(temp_dir, f"layer_{index}.tar")
        _download_blob(repository, layer.get("digest", ""), token, layer_path)
        _apply_layer_file(layer_path, rootfs_dir)

    return DockerImageInfo(
        target=image_ref,
        display_name=display_name,
        image_digest=manifest_digest,
        config_digest=config_descriptor.get("digest", ""),
        os_name=config.get("os"),
        os_version=None,
        os_arch=config.get("architecture"),
    )


def _parse_dockerhub_reference(image_ref: str) -> Tuple[str, str, str]:
    """解析 Docker Hub 镜像引用。

    Args:
        image_ref (str): 用户输入的 Docker Hub 镜像名。

    Returns:
        tuple: 仓库路径、tag 或 digest、展示名称。
    """

    if "://" in image_ref or not image_ref.strip():
        raise ValueError(f"Docker 镜像名称无效: {image_ref}")

    ref = image_ref.strip()
    first_component = ref.split("/", 1)[0]
    has_registry_component = "/" in ref and ("." in first_component or ":" in first_component)
    if has_registry_component and first_component not in ("docker.io", "index.docker.io"):
        raise ValueError("当前仅支持 Docker Hub 公共镜像名称，不支持其他镜像仓库地址。")
    if first_component in ("docker.io", "index.docker.io"):
        ref = ref.split("/", 1)[1] if "/" in ref else ""

    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last_component = ref.rsplit("/", 1)[-1]
    if ":" in last_component:
        ref, tag = ref.rsplit(":", 1)
    if "/" not in ref:
        ref = f"library/{ref}"
    if not ref or any(part in ("", ".", "..") for part in ref.split("/")):
        raise ValueError(f"Docker 镜像名称无效: {image_ref}")

    reference = digest or tag or "latest"
    display_name = f"{ref}:{tag or 'latest'}" if not digest else f"{ref}@{digest}"
    return ref, reference, display_name


def _fetch_dockerhub_token(repository: str) -> str:
    """获取 Docker Hub 匿名拉取 token。"""

    params = {
        "service": "registry.docker.io",
        "scope": f"repository:{repository}:pull",
    }
    try:
        response = requests.get(DOCKERHUB_AUTH_URL, params=params, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise ValueError(f"连接 Docker Hub 认证服务失败: {exc}") from exc
    if response.status_code != 200:
        raise ValueError(f"Docker Hub 认证失败，HTTP 状态码: {response.status_code}")
    token = response.json().get("token")
    if not token:
        raise ValueError("Docker Hub 认证响应中未包含 token。")
    return token


def _fetch_manifest(
    repository: str,
    reference: str,
    token: str,
) -> Tuple[Dict[str, Any], str]:
    """获取镜像 manifest 或 manifest list。"""

    url = f"{DOCKERHUB_REGISTRY_URL}/v2/{repository}/manifests/{quote(reference, safe=':@')}"
    headers = {"Accept": MANIFEST_ACCEPT, "Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise ValueError(f"连接 Docker Hub 获取镜像清单失败: {exc}") from exc
    if response.status_code == 404:
        raise ValueError(f"Docker Hub 中未找到镜像或标签: {repository}:{reference}")
    if response.status_code in (401, 403):
        raise ValueError("Docker Hub 拒绝访问该镜像，当前仅支持公共镜像匿名拉取。")
    if response.status_code >= 400:
        raise ValueError(f"Docker Hub 获取镜像清单失败，HTTP 状态码: {response.status_code}")
    return response.json(), response.headers.get("Docker-Content-Digest", reference)


def _fetch_blob_json(repository: str, digest: str, token: str) -> Dict[str, Any]:
    """获取并解析 Docker Registry JSON blob。"""

    if not digest:
        raise ValueError("Docker 镜像清单缺少 config digest。")
    url = f"{DOCKERHUB_REGISTRY_URL}/v2/{repository}/blobs/{digest}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise ValueError(f"下载 Docker 镜像配置失败: {exc}") from exc
    if response.status_code >= 400:
        raise ValueError(f"下载 Docker 镜像配置失败，HTTP 状态码: {response.status_code}")
    return response.json()


def _download_blob(repository: str, digest: str, token: str, target_path: str) -> None:
    """下载 Docker Registry layer blob 到本地临时文件。"""

    if not digest:
        raise ValueError("Docker 镜像层缺少 digest。")
    url = f"{DOCKERHUB_REGISTRY_URL}/v2/{repository}/blobs/{digest}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(
            url, headers=headers, timeout=REQUEST_TIMEOUT, stream=True)
    except requests.RequestException as exc:
        raise ValueError(f"下载 Docker 镜像层失败: {exc}") from exc
    if response.status_code >= 400:
        raise ValueError(f"下载 Docker 镜像层失败，HTTP 状态码: {response.status_code}")
    with open(target_path, "wb") as target:
        for chunk in response.iter_content(chunk_size=BLOB_CHUNK_SIZE):
            if chunk:
                target.write(chunk)


def _select_manifest_descriptor(
    index: Dict[str, Any],
    platform: Tuple[str, str, Optional[str]],
) -> Dict[str, Any]:
    """从 manifest list 或 OCI index 中选择指定平台的 manifest。"""

    for descriptor in index.get("manifests", []):
        descriptor_platform = descriptor.get("platform") or {}
        if _platform_matches(descriptor_platform, platform):
            return descriptor
    platform_text = "/".join(field for field in platform if field)
    raise ValueError(f"Docker 镜像不包含指定平台 {platform_text} 的清单。")


def _platform_matches(
    descriptor_platform: Dict[str, Any],
    platform: Tuple[str, str, Optional[str]],
) -> bool:
    """判断 manifest descriptor 是否匹配目标平台。"""

    os_name, arch, variant = platform
    if descriptor_platform.get("os") != os_name:
        return False
    if descriptor_platform.get("architecture") != arch:
        return False
    if variant and descriptor_platform.get("variant") != variant:
        return False
    return True


def _ensure_config_matches_platform(
    config: Dict[str, Any],
    platform: Tuple[str, str, Optional[str]],
) -> None:
    """确认镜像 config 与目标平台兼容。"""

    os_name, arch, _ = platform
    config_os = config.get("os")
    config_arch = config.get("architecture")
    if config_os and config_os != os_name:
        raise ValueError(f"Docker 镜像平台不匹配: 期望 {os_name}，实际 {config_os}。")
    if config_arch and config_arch != arch:
        raise ValueError(f"Docker 镜像架构不匹配: 期望 {arch}，实际 {config_arch}。")


def _read_json_member(archive: tarfile.TarFile, member_name: str) -> Dict[str, Any]:
    """从 tar 归档中读取 JSON 成员。"""

    try:
        member_file = archive.extractfile(member_name)
    except KeyError as exc:
        raise ValueError(f"离线 Docker 镜像缺少文件: {member_name}") from exc
    if member_file is None:
        raise ValueError(f"离线 Docker 镜像文件无法读取: {member_name}")
    with member_file:
        return json.loads(member_file.read().decode("utf-8"))


def _apply_archive_layer(
    archive: tarfile.TarFile,
    layer_name: str,
    rootfs_dir: str,
) -> None:
    """从外层镜像 tar 中读取并应用一个 layer。"""

    try:
        layer_file = archive.extractfile(layer_name)
    except KeyError as exc:
        raise ValueError(f"离线 Docker 镜像缺少层文件: {layer_name}") from exc
    if layer_file is None:
        raise ValueError(f"离线 Docker 镜像层文件无法读取: {layer_name}")
    with layer_file:
        _apply_layer_stream(layer_file, rootfs_dir)


def _apply_layer_file(layer_path: str, rootfs_dir: str) -> None:
    """从本地 layer 文件应用一个 Docker 镜像层。"""

    try:
        with tarfile.open(layer_path, "r:*") as layer_tar:
            _apply_layer_members(layer_tar, rootfs_dir)
    except tarfile.TarError as exc:
        raise ValueError(f"Docker 镜像层无法解析: {exc}") from exc


def _apply_layer_stream(layer_file: BinaryIO, rootfs_dir: str) -> None:
    """从流式 layer 文件对象应用一个 Docker 镜像层。"""

    try:
        with tarfile.open(fileobj=layer_file, mode="r|*") as layer_tar:
            _apply_layer_members(layer_tar, rootfs_dir)
    except tarfile.TarError as exc:
        raise ValueError(f"Docker 镜像层无法解析: {exc}") from exc


def _apply_layer_members(layer_tar: tarfile.TarFile, rootfs_dir: str) -> None:
    """按 overlay 语义将 layer 成员应用到最终文件系统目录。"""

    for member in layer_tar:
        normalized = _normalize_member_path(member.name)
        if not normalized:
            continue
        basename = os.path.basename(normalized)
        dirname = os.path.dirname(normalized)
        if basename == ".wh..wh..opq":
            _clear_directory(os.path.join(rootfs_dir, dirname))
            continue
        if basename.startswith(".wh."):
            target_name = basename[len(".wh."):]
            _remove_path(os.path.join(rootfs_dir, dirname, target_name))
            continue

        target_path = os.path.join(rootfs_dir, normalized)
        if member.isdir():
            os.makedirs(target_path, exist_ok=True)
        elif member.isreg():
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            _remove_path(target_path)
            source = layer_tar.extractfile(member)
            if source is None:
                continue
            with source, open(target_path, "wb") as target:
                shutil.copyfileobj(source, target)
        elif member.issym() or member.islnk():
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            _remove_path(target_path)
            try:
                os.symlink(member.linkname, target_path)
            except OSError:
                continue


def _normalize_member_path(path: str) -> Optional[str]:
    """清洗 layer 内部路径，避免绝对路径或目录穿越。"""

    normalized = os.path.normpath(path.replace("\\", "/").lstrip("/"))
    if normalized in ("", ".") or normalized.startswith("../") or normalized == "..":
        return None
    return normalized


def _clear_directory(path: str) -> None:
    """清空 opaque whiteout 指向的目录内容。"""

    if not os.path.isdir(path):
        return
    for name in os.listdir(path):
        _remove_path(os.path.join(path, name))


def _remove_path(path: str) -> None:
    """删除文件、链接或目录。"""

    if os.path.islink(path) or os.path.isfile(path):
        os.remove(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)


def _has_dpkg_database(rootfs_dir: str) -> bool:
    """判断 rootfs 是否包含 dpkg 状态数据库。"""

    return os.path.isfile(os.path.join(rootfs_dir, "var/lib/dpkg/status"))


def _has_rpm_database(rootfs_dir: str) -> bool:
    """判断 rootfs 是否包含 RPM 数据库。"""

    candidates = (
        "var/lib/rpm/Packages",
        "var/lib/rpm/rpmdb.sqlite",
        "usr/lib/sysimage/rpm/Packages",
        "usr/lib/sysimage/rpm/rpmdb.sqlite",
    )
    return any(os.path.exists(os.path.join(rootfs_dir, candidate)) for candidate in candidates)


def _scan_dpkg_rootfs(
    rootfs_dir: str,
    image_info: DockerImageInfo,
    created_time: str,
    disable_tqdm: bool,
) -> Dict[str, Any]:
    """扫描 Debian/Ubuntu 系镜像 rootfs 中的 dpkg 数据库。"""

    originators = read_data_from_json(os.path.join(ASSIST_DIR, "originators.json"))
    status_path = os.path.join(rootfs_dir, "var/lib/dpkg/status")
    info_dir = os.path.join(rootfs_dir, "var/lib/dpkg/info")
    package_file_paths, package_md5sums = _read_dpkg_info_files(info_dir)
    packages = []
    files = []
    file_relationships = []
    licenses = []

    for fields in _parse_dpkg_status(status_path):
        name = fields.get("Package")
        if not name or "install ok installed" not in fields.get("Status", ""):
            continue
        architecture = fields.get("Architecture", "")
        checksum = _metadata_sha1(fields)
        package = Package(
            name, fields.get("Version", ""), None, architecture,
            "deb", "SHA1", checksum)
        package.set_description(fields.get("Description", "NOASSERTION"))
        package.set_source(fields.get("Source", "NOASSERTION"))
        for dependency in _split_dpkg_dependencies(fields.get("Depends", "")):
            package.add_declared_dep(dependency)
        for dependency in _split_dpkg_dependencies(fields.get("Pre-Depends", "")):
            package.add_declared_dep(dependency)

        originator_name, _, originators = extract_originator_name(
            fields.get("Homepage"), originators)
        suppliers = get_suppliers(
            fields.get("Maintainer", ""), fields.get("Homepage", ""),
            originator_name, DEB_SUPPLIERS)
        for supplier in suppliers:
            package.add_supplier(supplier)

        package_key = _select_dpkg_info_key(
            name, architecture, package_file_paths, package_md5sums)
        package_files = _build_dpkg_files(
            package_key, package_file_paths, package_md5sums)
        for file_info in package_files:
            package.add_file(file_info)
        package_licenses = _read_dpkg_package_licenses(rootfs_dir, name)
        for license_info in package_licenses:
            package.add_license(license_info.get("id"))

        packages.append(package)
        files.extend(package.files)
        file_relationships.extend(package.get_file_relationships())
        licenses.extend(package_licenses)

    if not packages:
        raise ValueError("Docker 镜像内的 dpkg 数据库未包含已安装软件包。")

    packages_sbom = [package.get_json() for package in packages]
    packages_sbom.sort(key=lambda item: item.get("name", ""))
    package_relationships = get_deb_relationships(packages_sbom, disable_tqdm)
    return _build_docker_sbom(
        packages_sbom, remove_duplicates(files), file_relationships,
        remove_duplicates(licenses), package_relationships, image_info,
        created_time)


def _scan_rpm_rootfs(
    rootfs_dir: str,
    image_info: DockerImageInfo,
    created_time: str,
    disable_tqdm: bool,
) -> Dict[str, Any]:
    """扫描 RPM 系镜像 rootfs 中的 RPM 数据库。"""

    originators = read_data_from_json(os.path.join(ASSIST_DIR, "originators.json"))
    db_args = _detect_rpm_db_args(rootfs_dir)
    package_rows = _run_rpm_query(
        rootfs_dir, db_args,
        ["-qa", "--qf", "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{LICENSE}\t%{URL}\t%{SUMMARY}\t%{SOURCERPM}\n"])
    packages = []
    files = []
    file_relationships = []
    licenses = []
    provides_relationships = []

    for row in package_rows.splitlines():
        columns = row.split("\t")
        if len(columns) < 8:
            continue
        name, version, release, arch, license_text, homepage, summary, source_rpm = columns[:8]
        checksum = _metadata_sha1({
            "name": name,
            "version": version,
            "release": release,
            "arch": arch,
        })
        package = Package(name, version, release, arch, "rpm", "SHA1", checksum)
        package.set_description(summary or "NOASSERTION")
        package.set_source(source_rpm or "NOASSERTION")
        originator_name, _, originators = extract_originator_name(homepage, originators)
        for supplier in get_suppliers(release, homepage, originator_name, RPM_SUPPLIERS):
            package.add_supplier(supplier)
        for dependency in _run_rpm_query(
                rootfs_dir, db_args, ["-q", "--requires", name]).splitlines():
            if dependency and not dependency.startswith("rpmlib("):
                package.add_declared_dep(dependency)
        provides = [
            item for item in _run_rpm_query(
                rootfs_dir, db_args, ["-q", "--provides", name]).splitlines()
            if item
        ]
        provides_relationships.append({"id": package.id, "provides": provides})
        for file_info in _build_rpm_files(rootfs_dir, db_args, name):
            package.add_file(file_info)
        package_licenses = rpm_licenses_scanner(license_text)
        for license_info in package_licenses:
            package.add_license(license_info.get("id"))

        packages.append(package)
        files.extend(package.files)
        file_relationships.extend(package.get_file_relationships())
        licenses.extend(package_licenses)

    if not packages:
        raise ValueError("Docker 镜像内的 RPM 数据库未包含已安装软件包。")

    packages_sbom = [package.get_json() for package in packages]
    packages_sbom.sort(key=lambda item: item.get("name", ""))
    package_relationships = get_rpm_relationships(
        packages_sbom, provides_relationships, disable_tqdm)
    return _build_docker_sbom(
        packages_sbom, remove_duplicates(files), file_relationships,
        remove_duplicates(licenses), package_relationships, image_info,
        created_time)


def _parse_dpkg_status(status_path: str) -> List[Dict[str, str]]:
    """解析 dpkg status 文件。"""

    with open(status_path, "r", encoding="utf-8", errors="replace") as status_file:
        content = status_file.read()
    paragraphs = re.split(r"\n\s*\n", content.strip())
    return [_parse_dpkg_paragraph(paragraph) for paragraph in paragraphs if paragraph.strip()]


def _parse_dpkg_paragraph(paragraph: str) -> Dict[str, str]:
    """解析 dpkg control 段落为字段字典。"""

    fields = {}
    current_key = None
    for line in paragraph.splitlines():
        if line.startswith(" ") and current_key:
            fields[current_key] += "\n" + line[1:]
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        current_key = key
        fields[key] = value.strip()
    return fields


def _read_dpkg_info_files(
    info_dir: str,
) -> Tuple[Dict[str, List[str]], Dict[str, Dict[str, str]]]:
    """读取 dpkg info 目录中的文件列表和 md5sums。"""

    file_paths = {}
    md5sums = {}
    if not os.path.isdir(info_dir):
        return file_paths, md5sums
    for file_name in os.listdir(info_dir):
        path = os.path.join(info_dir, file_name)
        if file_name.endswith(".list"):
            package_key = file_name[:-5]
            file_paths[package_key] = _read_lines(path)
        elif file_name.endswith(".md5sums"):
            package_key = file_name[:-8]
            md5sums[package_key] = _read_md5sums(path)
    return file_paths, md5sums


def _read_lines(path: str) -> List[str]:
    """读取文本文件中的非空行。"""

    with open(path, "r", encoding="utf-8", errors="replace") as source:
        return [line.strip() for line in source if line.strip()]


def _read_md5sums(path: str) -> Dict[str, str]:
    """读取 dpkg md5sums 文件。"""

    checksums = {}
    for line in _read_lines(path):
        parts = line.split(None, 1)
        if len(parts) == 2:
            checksums[f"/{parts[1].lstrip('/')}"] = parts[0]
    return checksums


def _select_dpkg_info_key(
    name: str,
    architecture: str,
    file_paths: Dict[str, List[str]],
    md5sums: Dict[str, Dict[str, str]],
) -> str:
    """选择 dpkg info 文件中与包匹配的 key。"""

    candidates = [f"{name}:{architecture}", name]
    available = set(file_paths) | set(md5sums)
    for candidate in candidates:
        if candidate in available:
            return candidate
    return name


def _build_dpkg_files(
    package_key: str,
    file_paths: Dict[str, List[str]],
    md5sums: Dict[str, Dict[str, str]],
) -> List[Dict[str, Any]]:
    """根据 dpkg 文件列表和 md5sums 构建 Linx 文件清单。"""

    checksums = md5sums.get(package_key, {})
    paths = sorted(checksums) if checksums else file_paths.get(package_key, [])
    files = []
    for path in paths:
        normalized_path = f"/{path.lstrip('/')}"
        basename = os.path.basename(normalized_path)
        if not basename:
            continue
        files.append(_build_file_info(
            normalized_path, "MD5", checksums.get(normalized_path, "NOASSERTION")))
    return files


def _read_dpkg_package_licenses(rootfs_dir: str, package_name: str) -> List[Dict[str, str]]:
    """从 Debian 版权文件中提取许可证信息。"""

    copyright_path = os.path.join(
        rootfs_dir, "usr/share/doc", package_name, "copyright")
    if not os.path.isfile(copyright_path):
        return []
    with open(copyright_path, "rb") as source:
        content = source.read().decode("utf-8", errors="replace")
    licenses = []
    for license_name in _extract_deb_license_list(content):
        licenses.append(_build_license_info(license_name))
    return licenses


def _split_dpkg_dependencies(dependencies: str) -> List[str]:
    """拆分 dpkg 依赖字段。"""

    return [field.strip() for field in dependencies.split(",") if field.strip()]


def _detect_rpm_db_args(rootfs_dir: str) -> List[str]:
    """根据 rootfs 中的 RPM 数据库位置生成 rpm 命令参数。"""

    if os.path.exists(os.path.join(rootfs_dir, "usr/lib/sysimage/rpm")):
        return ["--dbpath", "/usr/lib/sysimage/rpm"]
    return []


def _run_rpm_query(rootfs_dir: str, db_args: List[str], args: List[str]) -> str:
    """运行 rpm 查询命令。"""

    command = ["rpm", "--root", rootfs_dir, *db_args, *args]
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise ValueError("当前运行环境缺少 rpm 命令，无法扫描 RPM 系 Docker 镜像。") from exc
    if result.returncode != 0:
        logging.warning("RPM 查询失败: %s", result.stderr.strip())
        return ""
    return result.stdout


def _build_rpm_files(
    rootfs_dir: str,
    db_args: List[str],
    package_name: str,
) -> List[Dict[str, Any]]:
    """通过 rpm --dump 构建 RPM 包文件清单。"""

    files = []
    dump_output = _run_rpm_query(
        rootfs_dir, db_args, ["-q", "--dump", package_name])
    for line in dump_output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        checksum = fields[3] if fields[3] != "(none)" else "NOASSERTION"
        files.append(_build_file_info(fields[0], "MD5", checksum))
    return files


def _build_file_info(path: str, algorithm: str, checksum: str) -> Dict[str, Any]:
    """构建 Linx 文件元素。"""

    basename = os.path.basename(path)
    id_md5 = hashlib.md5(path.encode("utf-8")).hexdigest()[:12]
    return {
        "id": f"File-{basename}-{id_md5}",
        "name": basename,
        "path": path,
        "checksums": {
            "algorithm": algorithm,
            "value": checksum,
        },
    }


def _build_license_info(license_name: str) -> Dict[str, str]:
    """构建 Linx 许可证元素。"""

    return {
        "id": f"LicenseRef-{hashlib.md5(license_name.encode()).hexdigest()[:12]}",
        "name": license_name,
    }


def _build_docker_sbom(
    packages_sbom: List[Dict[str, Any]],
    files_sbom: List[Dict[str, Any]],
    file_relationships_sbom: List[Dict[str, Any]],
    licenses_sbom: List[Dict[str, Any]],
    package_relationships_sbom: List[Dict[str, Any]],
    image_info: DockerImageInfo,
    created_time: str,
) -> Dict[str, Any]:
    """构建 Docker 镜像扫描的 Linx SBOM 输出结构。"""

    metadata = {
        "image_name": image_info.display_name,
        "image_digest": image_info.image_digest or "NOASSERTION",
        "image_config_digest": image_info.config_digest or "NOASSERTION",
    }
    return {
        "packages_sbom": build_sbom_header(
            packages_sbom, "packages", image_info.target, created_time,
            image_info.os_name, image_info.os_version, image_info.os_arch,
            metadata),
        "files_sbom": build_sbom_header(
            files_sbom, "files", image_info.target, created_time,
            image_info.os_name, image_info.os_version, image_info.os_arch,
            metadata),
        "file_relationships_sbom": build_sbom_header(
            file_relationships_sbom, "file_relationships", image_info.target,
            created_time, image_info.os_name, image_info.os_version,
            image_info.os_arch, metadata),
        "licenses_sbom": build_sbom_header(
            licenses_sbom, "licenses", image_info.target, created_time,
            image_info.os_name, image_info.os_version, image_info.os_arch,
            metadata),
        "package_relationships_sbom": build_sbom_header(
            package_relationships_sbom, "package_relationships",
            image_info.target, created_time, image_info.os_name,
            image_info.os_version, image_info.os_arch, metadata),
    }


def _read_os_release(rootfs_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """读取 rootfs 中的 /etc/os-release。"""

    os_release_path = os.path.join(rootfs_dir, "etc/os-release")
    if not os.path.isfile(os_release_path):
        return None, None
    fields = {}
    with open(os_release_path, "r", encoding="utf-8", errors="replace") as source:
        for line in source:
            if "=" not in line:
                continue
            key, value = line.strip().split("=", 1)
            fields[key] = value.strip().strip('"')
    return fields.get("NAME") or fields.get("ID"), fields.get("VERSION_ID") or fields.get("VERSION")


def _blob_path_from_digest(digest: str) -> str:
    """将 OCI digest 转换为归档内 blob 路径。"""

    algorithm, _, value = digest.partition(":")
    if not algorithm or not value:
        raise ValueError(f"Docker 镜像 digest 无效: {digest}")
    return f"blobs/{algorithm}/{value}"


def _digest_from_blob_path(path: str) -> str:
    """从 blob 路径推断 digest。"""

    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 3 and parts[-2]:
        return f"{parts[-2]}:{parts[-1]}"
    return path


def _digest_for_text(text: str) -> str:
    """计算文本 SHA256 digest。"""

    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _metadata_sha1(metadata: Dict[str, Any]) -> str:
    """为已安装包元数据计算稳定 SHA1。"""

    payload = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()
