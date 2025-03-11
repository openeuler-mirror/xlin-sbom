from helper import ASSIST_DIR
from helper.json_helper import read_data_from_json, save_data_to_json
import os
import logging

creators_file_path = os.path.join(ASSIST_DIR, 'creators.json')


def repo_scanner(primary_xml_url, repo_url, created_time, disable_tqdm):
    packages = []
    licenses = []
    originators_file_path = os.path.join(ASSIST_DIR, 'originators.json')
    originators = read_data_from_json(originators_file_path)

    # TO-DO，从xml中获取packages，licenses和更新后的originators信息

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
        repo_url (str): 仓库的URL，通常指向一个包含 repodata 文件夹的目录。

    Returns:
        str or None: 如果找到 primary.xml.gz 文件，则返回其URL；否则返回 None。
    """

    import requests
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
            if "primary.xml.gz" in link['href']:
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
