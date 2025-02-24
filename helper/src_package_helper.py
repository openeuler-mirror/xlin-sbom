import os
import tarfile
import zipfile
import hashlib
from typing import Dict, Any
from helper.suppliers_helper import get_suppliers, RPM_SUPPLIERS
from helper.originators_helper import extract_originator_name
from helper.licenses_helper import rpm_licenses_scanner


def process_src_package(pkg_path: str, originators: Dict[str, Any]) -> Dict[str, Any]:
    """
    主处理函数，根据源码包类型分发到不同的处理流程
    """
    package_type = _detect_package_type(pkg_path)
    if package_type == 'rpm':
        return _process_spec(pkg_path, originators)
    elif package_type == 'deb':
        return _process_control(pkg_path, originators)
    else:
        return _process_other_package(pkg_path, originators)


def _detect_package_type(pkg_path: str) -> str:
    """
    检测源码包类型，返回rpm/deb/other
    """
    has_spec = False
    has_debian_control = False

    def _check_tar(members):
        nonlocal has_spec, has_debian_control
        for member in members:
            if isinstance(member, tarfile.TarInfo):
                if member.name.endswith('.spec'):
                    has_spec = True
                if 'debian/control' in member.name:
                    has_debian_control = True

    def _check_zip(names):
        nonlocal has_spec, has_debian_control
        for name in names:
            if name.endswith('.spec'):
                has_spec = True
            if 'debian/control' in name:
                has_debian_control = True

    ext = os.path.splitext(pkg_path)[1].lower()
    try:
        if ext in ('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar'):
            with tarfile.open(pkg_path, 'r:*') as tar:
                _check_tar(tar.getmembers())
        elif ext == '.zip':
            with zipfile.ZipFile(pkg_path, 'r') as z:
                _check_zip(z.namelist())
    except Exception as e:
        pass

    # 优先级判断
    if has_spec:
        return 'rpm'
    return 'deb' if has_debian_control else 'other'


def _process_spec(pkg_path: str, originators: Dict[str, Any]) -> Dict[str, Any]:
    """
    处理RPM源码包的主函数
    """
    # 计算校验和
    md5_value = _calculate_package_md5(pkg_path)

    # 提取spec文件内容
    spec_content = _extract_spec_content(pkg_path)
    if not spec_content:
        return {}

    # 解析spec文件
    spec_data = _parse_spec_content(spec_content)

    # 处理依赖项中的宏变量替换
    version = spec_data.get('version', '')
    release = spec_data.get('release', '')
    processed_depends = []
    for dep_data in spec_data.get('requires', []):
        dep_list = dep_data.split()
        for dep in dep_list:
            processed_depends.append(dep.replace(
                '%{version}', version).replace('%{release}', release))

    homepage = spec_data.get('url', '')
    originator_name, is_organization, originators = extract_originator_name(
        homepage, originators)
    suppliers = get_suppliers(
        release, homepage, originator_name, RPM_SUPPLIERS)
    licenses = rpm_licenses_scanner(spec_data.get('license', ''))
    license_id_list = [license.get("id") for license in licenses]

    # 构建返回数据结构
    package_info = {
        "id": f"Package-{spec_data.get('name', 'unknown')}-{md5_value}",
        "name": spec_data.get('name', ''),
        "version": version,
        "architecture": spec_data.get('architecture', ''),
        "package_type": "source",
        "depends": processed_depends,
        "licenses": license_id_list,
        "suppliers": suppliers,
        "description": spec_data.get('description', ''),
        "checksum": {
            "value": md5_value,
            "algorithm": "MD5"
        }
    }

    return package_info, licenses, originators


def _extract_spec_content(pkg_path: str) -> str:
    """
    从压缩包中提取spec文件内容
    """
    ext = os.path.splitext(pkg_path)[1].lower()
    try:
        if ext in ('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar'):
            with tarfile.open(pkg_path, 'r:*') as tar:
                spec_files = [
                    m for m in tar.getmembers() if m.name.endswith('.spec')]
                if spec_files:
                    f = tar.extractfile(spec_files[0])
                    return f.read().decode('utf-8', errors='ignore')
        elif ext == '.zip':
            with zipfile.ZipFile(pkg_path, 'r') as z:
                spec_files = [n for n in z.namelist() if n.endswith('.spec')]
                if spec_files:
                    with z.open(spec_files[0]) as f:
                        return f.read().decode('utf-8', errors='ignore')
    except Exception as e:
        pass
    return ''


def _calculate_package_md5(file_path: str) -> str:
    """
    计算源码包的MD5校验和
    """
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _parse_spec_content(spec_content: str) -> Dict[str, Any]:
    """
    解析spec文件内容的核心函数
    """
    parsed = {}
    current_section = None
    description_lines = []
    in_preamble = True  # 标志是否在preamble部分

    for line in spec_content.split('\n'):
        stripped_line = line.rstrip()

        # 处理section切换和preamble检测
        if stripped_line.startswith('%package') and in_preamble:
            in_preamble = False

        if stripped_line.startswith('%'):
            current_section = stripped_line.split()[0].lower()
            continue

        # 只在preamble部分处理主包字段
        if in_preamble:
            if stripped_line.lower().startswith('name:'):
                parsed['name'] = stripped_line.split(':', 1)[1].strip()
            elif stripped_line.lower().startswith('version:'):
                parsed['version'] = stripped_line.split(':', 1)[1].strip()
            elif stripped_line.lower().startswith('release:'):
                parsed['release'] = stripped_line.split(':', 1)[1].strip()
            elif stripped_line.lower().startswith('license:'):
                parsed['license'] = stripped_line.split(':', 1)[1].strip()
            elif stripped_line.lower().startswith('url:'):
                parsed['url'] = stripped_line.split(':', 1)[1].strip()
            elif stripped_line.lower().startswith('buildrequires:'):
                requires = [r.strip() for r in stripped_line.split(
                    ':', 1)[1].split(',') if r.strip()]
                parsed.setdefault('requires', []).extend(requires)
            elif stripped_line.lower().startswith('buildarch:'):
                parsed['architecture'] = stripped_line.split(':', 1)[1].strip()

            # 收集主包的%description内容（无参数的%description）
            if current_section == '%description':
                description_lines.append(stripped_line)

    # 合并描述内容
    if description_lines:
        parsed['description'] = ' '.join(
            [l.strip() for l in description_lines if l.strip()]
        )

    return parsed


def _process_control(pkg_path: str, originators: Dict[str, Any]) -> Dict[str, Any]:
    """
    处理DEB源码包的占位函数
    """
    # TODO: 实现DEB包处理逻辑
    return {
        "id": "",
        "name": "",
        "version": "",
        "architecture": "",
        "package_type": "source",
        "depends": [],
        "licenses": [],
        "release": "",
        "homepage": "",
        "description": "",
        "checksum": {
            "value": "",
            "algorithm": "MD5"
        }
    }


def _process_other_package(pkg_path: str, originators: Dict[str, Any]) -> Dict[str, Any]:
    """
    处理其他类型源码包的占位函数
    """
    # TODO: 实现其他类型处理逻辑
    return {
        "id": "",
        "name": "",
        "version": "",
        "architecture": "",
        "package_type": "source",
        "depends": [],
        "licenses": [],
        "release": "",
        "homepage": "",
        "description": "",
        "checksum": {
            "value": "",
            "algorithm": "MD5"
        }
    }
