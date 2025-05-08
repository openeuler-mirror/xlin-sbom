import tempfile
import os
import shutil
import logging
import hashlib
from tqdm import tqdm
from multiprocessing import Pool
from fnmatch import fnmatch
from scancode import api as scancode
from helper.data_helper import calculate_md5, remove_duplicates
from helper.licenses_helper import rpm_licenses_scanner


def _extract_src_rpm(src_rpm_path):
    """
    解压 .src.rpm 文件并提取其中的源代码压缩文件，返回解压后的源代码目录路径。

    Args:
        src_rpm_path (str): .src.rpm 文件的路径。

    Returns:
        str: 解压后的源代码目录路径。

    Raises:
        ValueError: 如果未在 .src.rpm 文件中找到源代码压缩文件。
    """

    import libarchive

    # 创建一个临时目录用于解压 .src.rpm 文件
    temp_dir = tempfile.mkdtemp()

    try:
        # 解压 .src.rpm 文件
        with libarchive.file_reader(src_rpm_path) as archive:
            for entry in archive:
                pathname = os.path.join(temp_dir, entry.pathname)
                if entry.isdir:
                    os.makedirs(pathname, exist_ok=True)
                elif entry.isfile:
                    with open(pathname, 'wb') as f:
                        for block in entry.get_blocks():
                            f.write(block)

        # 在解压后的文件中查找源代码压缩文件
        source_archive = None
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith(('.tar.xz', '.tar.gz', '.tgz', '.tar.bz2')):
                    source_archive = os.path.join(root, file)
                    break
            if source_archive:
                break

        if not source_archive:
            raise ValueError("未在 .src.rpm 文件中找到源代码压缩文件")

        # 创建一个临时目录用于解压源代码压缩文件
        source_dir = tempfile.mkdtemp()

        # 解压源代码压缩文件
        with libarchive.file_reader(source_archive) as archive:
            for entry in archive:
                pathname = os.path.join(source_dir, entry.pathname)
                if entry.isdir:
                    os.makedirs(pathname, exist_ok=True)
                elif entry.isfile:
                    with open(pathname, 'wb') as f:
                        for block in entry.get_blocks():
                            f.write(block)

        # 返回解压后的源代码目录路径
        return source_dir

    finally:
        # 清理 .src.rpm 的临时目录
        shutil.rmtree(temp_dir)


def _should_include(member_name, include_patterns, exclude_patterns):
    """
    判断一个文件或目录名是否应该被包含在处理范围内。

    Args:
        member_name (str): 文件或目录的名称。
        include_patterns (list): 要包含的文件模式列表（可以为空）。 · 
        exclude_patterns (list): 要排除的文件模式列表（可以为空）。

    Returns:
        bool: 如果文件或目录名符合包含模式且不符合排除模式，则返回True；否则返回False。
    """

    if include_patterns:
        if not any(fnmatch(member_name, pattern) for pattern in include_patterns):
            return False
    if exclude_patterns:
        if any(fnmatch(member_name, pattern) for pattern in exclude_patterns):
            return False
    return True


def _process_member(member_path):
    """
    处理指定的文件成员，提取其许可证、版权信息以及其他元数据。

    Args:
        member_path (str): 文件系统的路径，指向需要处理的文件。

    Returns:
        tuple: 包含两个元素：
            - file_info (dict): 提取的文件信息，包括以下字段：
                - id (str): 文件的唯一标识符，由文件名和MD5哈希值生成。
                - name (str): 文件名。
                - path (str): 文件的处理后路径。
                - licenses (list of str): 检测到的许可证ID列表。
                - holders (list of str): 版权持有者列表。
                - checksums (dict): 文件的校验信息，包含算法（algorithm）和值（value）。
            - license_id_list (list of str): 许可证扫描器返回的许可证ID列表。
    """

    licenses = scancode.get_licenses(location=member_path, include_text=True)
    copyright_data = scancode.get_copyrights(location=member_path)

    detected_license_expression_spdx = licenses.get(
        'detected_license_expression_spdx')
    holders = list(set(item['holder']
                   for item in copyright_data.get('holders', [])))

    # 处理 member_path
    parts = member_path.split('/')
    if parts[0] == '':
        new_parts = [''] + parts[4:]
    else:
        new_parts = parts[3:]
    processed_file_path = '/'.join(new_parts)

    id_md5 = hashlib.md5(processed_file_path.encode()).hexdigest()[:12]
    name = os.path.basename(member_path)
    if detected_license_expression_spdx:
        licenses = rpm_licenses_scanner(detected_license_expression_spdx)
        license_id_list = [license.get("id") for license in licenses]
    else:
        licenses = []
        license_id_list = []

    with open(member_path, 'rb') as f:
        file_md5 = calculate_md5(f)

    file_info = {
        "id": f"File-{name}-{id_md5}",
        "name": name,
        "path": processed_file_path,
        "licenses": license_id_list,
        "holders": holders,
        "checksums": {
            "algorithm": "MD5",
            "value": file_md5
        }
    }

    return file_info, licenses


def scan_src_rpm(src_rpm_path, include, exclude, workers, disable_tqdm):
    """
    扫描 .src.rpm 文件中的源代码文件，提取每个文件的元数据和许可证信息。

    Args:
        src_rpm_path (str): .src.rpm 文件的路径。
        include (list of str): 要包含的文件模式列表（例如 ['*.c', '*.h']）。
        exclude (list of str): 要排除的文件模式列表（例如 ['test/*', '*.log']）。
        workers (int or None): 并行处理文件的进程数。如果为 None，则使用默认值 4。
        disable_tqdm (bool): 是否禁用进度条显示。

    Returns:
        tuple: 包含两个元素：
            - file_list (list of dict): 每个文件的信息，包括：
                - id (str): 文件的唯一标识符。
                - name (str): 文件名。
                - path (str): 文件路径。
                - licenses (list of str): 检测到的许可证 ID 列表。
                - holders (list of str): 版权持有者列表。
                - checksums (dict): 文件的校验值，包含算法和值。
            - license_list (list of dict): 所有检测到的许可证信息列表，去重后。
    """

    source_dir = _extract_src_rpm(src_rpm_path)
    members = []
    file_list = []
    license_list = []

    for root, dirs, files in os.walk(source_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if _should_include(file_path, include, exclude):
                members.append(file_path)
    total_files = len(members)

    # 使用多进程来处理文件
    if workers is None:
        logging.info("使用默认的线程数进行扫描")
        workers = 4
    else:
        logging.info(f"使用 {workers} 个线程进行扫描")

    with Pool(processes=workers) as pool:
        for file_info, licenses in tqdm(pool.imap_unordered(_process_member, members), total=total_files, desc="扫描文件：", disable=disable_tqdm):
            if file_info:
                file_list.append(file_info)
            if licenses:
                license_list.extend(licenses)

    license_list = remove_duplicates(license_list)

    # 通过文件ID排序
    file_list.sort(key=lambda x: x.get("id", ""))

    shutil.rmtree(source_dir)
    return file_list, license_list
