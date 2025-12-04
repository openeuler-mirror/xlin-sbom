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
from helper.data_helper import read_data_from_json, save_data_to_json, remove_duplicates
from helper.suppliers_helper import get_suppliers, RPM_SUPPLIERS, DEB_SUPPLIERS
from helper.originators_helper import extract_originator_name
from helper.licenses_helper import rpm_licenses_scanner
from typing import Any, Dict, List, Optional, Tuple, Union
from bs4 import BeautifulSoup
from urllib.parse import urljoin    
import xml.etree.ElementTree as ET
from tqdm import tqdm
import gzip
from io import BytesIO
import requests
import zstandard
import os
import logging

creators_file_path = os.path.join(ASSIST_DIR, 'creators.json')


def rpm_repo_scanner(
    primary_xml_url: str,
    repo_url: str,
    created_time: str,
    disable_tqdm: bool
) -> Dict[str, Dict[str, Any]]:
    """
    扫描指定的 primary.xml.gz 文件并生成软件包和许可证的 SBOM。

    Args:
        primary_xml_url (str): primary.xml.gz 文件的URL。
        repo_url (str): 更新源的URL。
        created_time (str): 创建时间的字符串。

    Returns:
        dict: 包含软件包和许可证 SBOM 的字典。
    """

    packages = []
    licenses = []
    originators_file_path = os.path.join(ASSIST_DIR, 'originators.json')
    originators = read_data_from_json(originators_file_path)

    metadata = _fetch_and_extract_metadata(primary_xml_url)
    if metadata:
        packages, licenses, originators = _parse_primary_xml(
            metadata, originators, disable_tqdm)

    linx_sbom = {
        "packages_sbom": _add_header(packages, "packages", repo_url, created_time),
        "licenses_sbom": _add_header(licenses, "licenses", repo_url, created_time),
    }

    # 保存更新后的发起者信息
    save_data_to_json(originators, originators_file_path)

    # 返回处理后的软件包信息列表
    return linx_sbom


def deb_repo_scanner(
    sources_url_list: List[str],
    repo_url: str,
    created_time: str,
    disable_tqdm: bool
) -> Dict[str, Dict[str, Any]]:
    """
    扫描指定的 Sources 文件并生成软件包和许可证的 SBOM。

    Args:
        sources_url (str): Sources 文件的URL。
        repo_url (str): 仓库的URL。
        created_time (str): 创建时间的字符串。

    Returns:
        dict: 包含软件包和许可证的 SBOM 的字典。
    """
    packages = []
    licenses = []
    originators_file_path = os.path.join(ASSIST_DIR, 'originators.json')
    originators = read_data_from_json(originators_file_path)

    for sources_url in sources_url_list:
        metadata = _fetch_and_extract_metadata(sources_url)
        if metadata:
            packages_, licenses_, originators = _parse_sources(
                metadata, originators, disable_tqdm)
            packages.extend(packages_)
            licenses.extend(licenses_)
    
    linx_sbom = {
        "packages_sbom": _add_header(packages, "packages", repo_url, created_time),
        "licenses_sbom": _add_header(licenses, "licenses", repo_url, created_time),
    }

    # 保存更新后的发起者信息
    save_data_to_json(originators, originators_file_path)
    
    return linx_sbom


def find_primary_xml_in_repo(repo_url: str) -> Optional[str]:
    """
    在给定的仓库URL中查找 primary.xml.gz 文件的URL。

    Args:
        repo_url (str): 更新源的URL，通常指向一个包含 repodata 文件夹的目录。

    Returns:
        str or None: 如果找到 primary.xml.gz 文件，则返回其URL；否则返回 None。
    """

    try:
        response = requests.get(repo_url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # 查找包含 repodata 文件夹的链接
        repodata_link = None
        for link in soup.find_all("a", href=True):
            if "repodata/" in link['href']:
                repodata_link = repo_url + link['href']
                break

        # 访问 repodata 目录，查找 primary.xml.gz
        response = requests.get(repodata_link)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a", href=True):
            if "primary.xml" in link['href']:
                return repodata_link + link['href']

    except requests.exceptions.RequestException as e:
        logging.error(f"获取repodata时发生错误: {e}")
        return None
    

def find_deb_sources_in_repo(repo_url: str) -> Optional[str]:
    """
    在给定的Debian仓库URL中查找Sources文件或其压缩包的URL。

    Args:
        repo_url (str): Debian更新源的URL，指向dists目录下的发行版目录，
                        例如: "http://ftp.cn.debian.org/debian/dists/Debian11.11/"

    Returns:
        List[str] or None: 如果找到Sources文件，则返回包含其URL的列表；否则返回None。
    """

    try:
        # 确保repo_url以斜杠结尾
        if not repo_url.endswith('/'):
            repo_url += '/'
        
        # Debian仓库的三个主要组件目录
        components = ["contrib", "main", "non-free"]
        sources_urls = []
        
        for component in components:
            try:
                # 构建组件目录的URL
                component_url = urljoin(repo_url, f"{component}/")
                
                # 尝试访问组件目录
                response = requests.get(component_url, timeout=10)
                response.raise_for_status()
                
                # 如果组件目录存在，查找其中的source目录
                soup = BeautifulSoup(response.text, "html.parser")
                source_link = None
                
                for link in soup.find_all("a", href=True):
                    href = link['href']
                    # 查找source目录（可能以'source/'或'source/'开头）
                    if 'source/' in href and href.rstrip('/').endswith('source'):
                        source_link = urljoin(component_url, href)
                        break
                
                if source_link:
                    # 访问source目录，查找Sources文件
                    source_response = requests.get(source_link, timeout=10)
                    source_response.raise_for_status()
                    source_soup = BeautifulSoup(source_response.text, "html.parser")
                    
                    # Sources文件可能的扩展名（按优先级排序）
                    possible_extensions = ['.gz', '.bz2', '.xz']
                    
                    for ext in possible_extensions:
                        sources_filename = f"Sources{ext}"
                        
                        for link in source_soup.find_all("a", href=True):
                            href = link['href']
                            # 检查是否匹配Sources文件（考虑可能的查询参数）
                            if href.startswith(sources_filename) or f"/{sources_filename}" in href:
                                sources_url = urljoin(source_link, href.split('?')[0])  # 去除查询参数
                                sources_urls.append(sources_url)
                                logging.info(f"在组件 {component} 中找到Sources文件: {sources_url}")
                                break
                        
                        # 如果找到该扩展名的文件，跳出扩展名循环
                        if any(sources_filename in url for url in sources_urls[-1:] if sources_urls):
                            break
            
            except requests.exceptions.RequestException as e:
                logging.debug(f"跳过组件 {component}: {e}")
                continue
        
        # 检查是否找到了至少一个Sources文件
        if sources_urls:
            return sources_urls
        else:
            logging.error(f"在仓库 {repo_url} 中未找到任何Sources文件")
            return None
    
    except requests.exceptions.RequestException as e:
        logging.error(f"获取仓库目录时发生错误: {e}")
        return None
    except Exception as e:
        logging.error(f"处理仓库时发生意外错误: {e}")
        return None


def _add_header(
    sbom_data: List[Dict[str, Any]],
    data_name: str,
    repo_url: str,
    created_time: str
) -> Dict[str, Any]:
    """
    为 SBOM 数据添加头部信息。

    Args:
        sbom_data (list): SBOM 数据列表。
        data_name (str): 数据类型名称（如 "packages"、"files" 等）。
        repo_url (str): 更新源的URL。
        created_time (str): 创建时间的字符串。

    Returns:
        dict: 包含头部信息的 SBOM 字典。
    """

    sbom = {
        "scan_target": repo_url or "NOASSERTION",
        "creation_info": {
            "creators": read_data_from_json(creators_file_path),
            "created": created_time
        },
        data_name: sbom_data
    }
    return sbom


def _fetch_and_extract_metadata(metadata_url: str) -> Optional[bytes]:

    try:
        response = requests.get(metadata_url)
        response.raise_for_status()

        content = response.content

        if metadata_url.endswith('.gz'):
            try:
                with gzip.GzipFile(fileobj=BytesIO(content)) as f:
                    return f.read()
            except gzip.BadGzipFile as e:
                logging.error(f"解压gzip失败: {e}")
                return None

        elif metadata_url.endswith('.zst'):
            try:
                # 流式解压
                dctx = zstandard.ZstdDecompressor()
                decompressed = bytearray()
                with dctx.stream_reader(BytesIO(content)) as reader:
                    while True:
                        chunk = reader.read(16384)
                        if not chunk:
                            break
                        decompressed.extend(chunk)
                return bytes(decompressed)
            except zstandard.ZstdError as e:
                logging.error(f"解压zst失败: {e}")
                return None

        else:
            logging.error(f"不支持的格式: {metadata_url}")
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"下载失败: {e}")
        return None


def _parse_primary_xml(
    xml_data: bytes,
    originators: List[Dict[str, Any]],
    disable_tqdm: bool = False
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    解析 primary.xml 数据并提取软件包和许可证信息。

    Args:
        xml_data (bytes): primary.xml 文件的解压后数据。
        originators (list): 发起者信息列表。
        disable_tqdm (bool): 是否禁用tqdm进度条，默认为False显示进度条。

    Returns:
        tuple: 包含解析后的软件包列表、许可证列表和更新后的发起者信息列表的元组。
            - packages (list): 软件包信息列表。
            - licenses (list): 许可证信息列表。
            - originators (list): 更新后的发起者信息列表。
    """

    tree = ET.ElementTree(ET.fromstring(xml_data))
    root = tree.getroot()

    namespaces = {
        "ns0": "http://linux.duke.edu/metadata/common",
        "rpm": "http://linux.duke.edu/metadata/rpm"
    }

    packages = []
    licenses = []

    for package in tqdm(root.findall("ns0:package", namespaces), disable=disable_tqdm):
        try:
            name = package.findtext("ns0:name", namespaces=namespaces)
            ver = package.find("ns0:version", namespaces).attrib.get("ver", '')
            rel = package.find("ns0:version", namespaces).attrib.get("rel", '')

            homepage = package.findtext("ns0:url", namespaces=namespaces)
            originator_name, is_organization, originators = extract_originator_name(
                homepage, originators)
            suppliers = get_suppliers(
                rel, homepage, originator_name, RPM_SUPPLIERS)

            licenses_ = rpm_licenses_scanner(package.findtext(
                "ns0:format/rpm:license", namespaces=namespaces))
            license_id_list = [license.get("id") for license in licenses_]
            licenses.extend(licenses_)

            checksum = package.findtext("ns0:checksum", namespaces=namespaces)
            source = package.findtext(
                "ns0:format/rpm:sourcerpm", namespaces=namespaces)

            package_info = {
                "id": f"Package-{name}-{checksum[:12]}",
                "name": name,
                "version": f"{ver}-{rel}",
                "architecture": package.findtext("ns0:arch", namespaces=namespaces),
                "package_type": "rpm",
                "depends": [],
                "sourcerpm": source,
                "licenses": license_id_list,
                "suppliers": suppliers,
                "description": package.findtext("ns0:description", namespaces=namespaces),
                "checksum": {
                    "value": checksum,
                    "algorithm": package.find("ns0:checksum", namespaces).attrib.get("type", ''),
                }
            }

            for require in package.findall("ns0:format/rpm:requires/rpm:entry", namespaces):
                package_info["depends"].append(
                    require.attrib.get("name", None))

            packages.append(package_info)

        except Exception as e:
            logging.error(f"解析包 {name} 时发生错误: {e}")
            continue

    licenses = remove_duplicates(licenses)
    return packages, licenses, originators


def _parse_sources(
    sources_data: bytes,
    originators: List[Dict[str, Any]],
    disable_tqdm: bool = False
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    
    # 将bytes转换为字符串
    text_data = sources_data.decode('utf-8')
    
    packages = []
    
    # 按空行分割不同的包信息
    package_blocks = text_data.strip().split('\n\n')
    
    for block in tqdm(package_blocks, disable=disable_tqdm):
        try:
            package_info = {}
            
            # 解析块中的字段
            lines = block.split('\n')
            current_field = None
            field_data = {}
            
            for line in lines:
                # 检查是否是字段开始（不以空格开头）
                if line and not line.startswith(' '):
                    # 处理多行字段的累积
                    if current_field and current_field in field_data:
                        if isinstance(field_data[current_field], list):
                            field_data[current_field] = '\n'.join(field_data[current_field])
                    
                    # 解析新字段
                    if ':' in line:
                        field_name, field_value = line.split(':', 1)
                        field_name = field_name.strip()
                        field_value = field_value.strip()
                        
                        # 对于多行字段，初始化为列表
                        if field_name in ['Files', 'Checksums-Sha256', 'Package-List']:
                            field_data[field_name] = [field_value] if field_value else []
                        else:
                            field_data[field_name] = field_value
                        
                        current_field = field_name
                elif current_field and line.strip():
                    # 多行字段的延续
                    if current_field in field_data and isinstance(field_data[current_field], list):
                        field_data[current_field].append(line.strip())
            
            # 处理最后一个字段
            if current_field and current_field in field_data:
                if isinstance(field_data[current_field], list):
                    field_data[current_field] = '\n'.join(field_data[current_field])
            
            # 提取所需信息
            name = field_data.get('Package', '')
            version = field_data.get('Version', '')
            homepage = field_data.get('Homepage', '')
            
            # 使用与primary.xml相同的逻辑处理originator
            originator_name, is_organization, originators = extract_originator_name(
                homepage, originators
            )
            
            # 获取suppliers，使用DEB_SUPPLIERS
            suppliers = get_suppliers(
                "debian", homepage, originator_name, DEB_SUPPLIERS
            )
            
            # 提取orig.tar包的SHA256哈希值
            checksum_value = ''
            if 'Checksums-Sha256' in field_data:
                checksum_lines = field_data['Checksums-Sha256'].split('\n')
                for line in checksum_lines:
                    parts = line.strip().split()
                    if len(parts) >= 3 and '.orig.tar.' in parts[2]:
                        checksum_value = parts[0]
                        break
            
            # 构建package_info字典
            package_info = {
                "id": f"Package-{name}-{checksum_value[:12] if checksum_value else 'unknown'}",
                "name": name,
                "version": version,
                "architecture": "source",
                "package_type": "source",
                "depends": [],
                "licenses": [],
                "suppliers": suppliers,
                "description": "",
                "checksum": {
                    "value": checksum_value,
                    "algorithm": "Sha256",
                }
            }
            
            packages.append(package_info)
            
        except Exception as e:
            logging.error(f"解析包 {field_data.get('Package', 'unknown')} 时发生错误: {e}")
            continue
    
    # 返回结果，licenses始终为空列表
    return packages, [], originators