from helper import ASSIST_DIR
from helper.json_helper import read_data_from_json, save_data_to_json
from helper.suppliers_helper import get_suppliers, RPM_SUPPLIERS
from helper.originators_helper import extract_originator_name
from helper.licenses_helper import rpm_licenses_scanner
from helper.iso_helper import remove_duplicates
import os
import logging
import requests

creators_file_path = os.path.join(ASSIST_DIR, 'creators.json')


def repo_scanner(primary_xml_url, repo_url, created_time):
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

    xml_data = _fetch_and_extract_xml(primary_xml_url)
    if xml_data:
        packages, licenses, originators = _parse_primary_xml(
            xml_data, originators)

    linx_sbom = {
        "packages_sbom": _add_header(packages, "packages", repo_url, created_time),
        "licenses_sbom": _add_header(licenses, "licenses", repo_url, created_time),
    }

    # 保存更新后的发起者信息
    save_data_to_json(originators, originators_file_path)

    # 返回处理后的软件包信息列表
    return linx_sbom


def find_primary_xml_in_repo(repo_url):
    """
    在给定的仓库URL中查找 primary.xml.gz 文件的URL。

    Args:
        repo_url (str): 更新源的URL，通常指向一个包含 repodata 文件夹的目录。

    Returns:
        str or None: 如果找到 primary.xml.gz 文件，则返回其URL；否则返回 None。
    """

    from bs4 import BeautifulSoup

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


def _add_header(sbom_data, data_name, repo_url, created_time):
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
        "repo_url": repo_url or "NOASSERTION",
        "creation_info": {
            "creators": read_data_from_json(creators_file_path),
            "created": created_time
        },
        data_name: sbom_data
    }
    return sbom


def _fetch_and_extract_xml(primary_xml_url):
    import gzip
    from io import BytesIO
    import logging
    import requests
    import zstandard

    try:
        response = requests.get(primary_xml_url)
        response.raise_for_status()

        content = response.content

        if primary_xml_url.endswith('.gz'):
            try:
                with gzip.GzipFile(fileobj=BytesIO(content)) as f:
                    return f.read()
            except gzip.BadGzipFile as e:
                logging.error(f"解压gzip失败: {e}")
                return None

        elif primary_xml_url.endswith('.zst'):
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
            logging.error(f"不支持的格式: {primary_xml_url}")
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"下载失败: {e}")
        return None


def _parse_primary_xml(xml_data, originators):
    """
    解析 primary.xml 数据并提取软件包和许可证信息。

    Args:
        xml_data (bytes): primary.xml 文件的解压后数据。
        originators (list): 发起者信息列表。

    Returns:
        tuple: 包含解析后的软件包列表、许可证列表和更新后的发起者信息列表的元组。
            - packages (list): 软件包信息列表。
            - licenses (list): 许可证信息列表。
            - originators (list): 更新后的发起者信息列表。
    """
    
    import xml.etree.ElementTree as ET

    tree = ET.ElementTree(ET.fromstring(xml_data))
    root = tree.getroot()

    namespaces = {
        "ns0": "http://linux.duke.edu/metadata/common",
        "rpm": "http://linux.duke.edu/metadata/rpm"
    }

    packages = []
    licenses = []

    for package in root.findall("ns0:package", namespaces):
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
                "ns0:format/rpm:sourcerpm", namespaces=namespaces)  # TO-DO

            package_info = {
                "id": f"Package-{name}-{checksum}",
                "name": name,
                "version": f"{ver}-{rel}",
                "architecture": package.findtext("ns0:arch", namespaces=namespaces),
                "package_type": "rpm",
                "depends": [],
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
