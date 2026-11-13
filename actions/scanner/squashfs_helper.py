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

"""解析 live-boot/casper 的 filesystem.module 并叠加多层 squashfs。

ISO 中的 filesystem.module 按从底层到顶层的顺序列出 squashfs 镜像，
live-boot 会把它们作为 overlayfs 的多个 lowerdir 叠加，其中最后列出的
镜像优先级最高。本模块按同样的顺序把各层解包到同一个目录，后解包的层
覆盖先解包的层，从而复现运行时可见的 rootfs。
"""

from contextlib import contextmanager
from dataclasses import dataclass
import logging
import os
import posixpath
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

SQUASHFS_SUFFIX = ".squashfs"
MODULE_NAME = "filesystem.module"
SIZE_HINT_NAME = "filesystem.size"
IMAGE_DIRECTORIES = ("live", "casper")
WHITEOUT_PREFIX = ".wh."
WHITEOUT_OPAQUE = ".wh..wh..opq"
WORK_DIR_PREFIX = "linx_iso_rootfs_"
# 解压之外的余量：层镜像副本、dpkg 查询临时文件等。
SPACE_SLACK_BYTES = 1 << 30
# 解压失败后剩余空间低于该值时判定为磁盘写满。
LOW_SPACE_BYTES = 64 << 20


@dataclass(frozen=True)
class SquashfsLayer:
    """描述 filesystem.module 中声明的一个 squashfs 层。"""

    entry: Any
    listed_path: str
    order: int


def discover_layers(
    reader: Any,
    entries: Iterable[Any],
    work_dir: str,
) -> List[SquashfsLayer]:
    """按叠加顺序（底层在前、顶层在后）返回 ISO 中的 squashfs 层。

    Args:
        reader: ISO 读取器，需提供 extract_file(entry, target_path)。
        entries: ISO 内的文件条目列表。
        work_dir: 用于暂存 filesystem.module 的临时目录。

    Returns:
        list: SquashfsLayer 列表；未发现 squashfs rootfs 时返回空列表。
    """

    entries = list(entries)
    index = _build_path_index(entries)
    for module_entry in _candidate_module_entries(entries):
        layers = _layers_from_module(reader, module_entry, index, entries, work_dir)
        if layers:
            logging.info(
                "检测到 %s，按文件列表叠加 %d 个 squashfs 层",
                module_entry.display_path, len(layers))
            for layer in layers:
                logging.info("  squashfs 层 %d: %s",
                             layer.order, layer.entry.display_path)
            return layers

    layers = [
        SquashfsLayer(entry, entry.display_path, order)
        for order, entry in enumerate(_fallback_entries(entries), 1)
    ]
    if layers:
        logging.info(
            "未找到 filesystem.module，按目录内默认顺序叠加 %d 个 squashfs 层",
            len(layers))
    return layers


def read_expected_size(
    reader: Any,
    entries: Iterable[Any],
    work_dir: str,
) -> Optional[int]:
    """读取 live-boot 的 filesystem.size，返回 rootfs 解压后的字节数。

    live-boot/casper 把 rootfs 解压后的总字节数写在 filesystem.size 中，
    该值用于在展开前检查工作目录容量。文件缺失或内容非法时返回 None。

    Args:
        reader: ISO 读取器，需提供 extract_file(entry, target_path)。
        entries: ISO 内的文件条目列表。
        work_dir: 用于暂存 filesystem.size 的临时目录。

    Returns:
        int | None: 解压后字节数；无法确定时返回 None。
    """

    for entry in _candidate_size_entries(list(entries)):
        size_path = os.path.join(work_dir, SIZE_HINT_NAME)
        try:
            reader.extract_file(entry, size_path)
            with open(size_path, "r", encoding="utf-8", errors="replace") as source:
                raw = source.read(64).strip()
        except Exception as exc:
            logging.warning("读取 %s 失败，忽略该文件: %s",
                            entry.display_path, exc)
            continue
        finally:
            try:
                os.remove(size_path)
            except OSError:
                pass

        try:
            size = int(raw)
        except ValueError:
            logging.warning("%s 内容不是字节数，已忽略: %r",
                            entry.display_path, raw)
            continue
        if size <= 0:
            logging.warning("%s 内容不是有效大小，已忽略: %r",
                            entry.display_path, raw)
            continue
        logging.info("%s 声明 rootfs 解压后约 %s", entry.display_path,
                     _format_bytes(size))
        return size
    return None


def required_work_space(expected_size: Optional[int]) -> Optional[int]:
    """返回展开 squashfs 层所需的工作目录空间；无法确定时返回 None。"""

    if expected_size is None:
        return None
    return expected_size + SPACE_SLACK_BYTES


@contextmanager
def work_directory(
    requested: Optional[str] = None,
    required_bytes: Optional[int] = None,
    candidates: Iterable[str] = (),
) -> Iterator[str]:
    """分配展开 squashfs 层的工作目录，并在退出时清理。

    未指定目录时依次尝试系统临时目录、调用方给出的候选目录，选第一个
    可用空间满足要求的目录；临时目录常为 tmpfs（占用内存且容量小），
    多层 live 镜像解压后的 rootfs 可达数十 GB，必须能落到真实磁盘上。

    Args:
        requested: 用户指定的工作目录；指定后不再自动改用其他目录。
        required_bytes: 需要的可用空间字节数；None 表示未知，不做容量检查。
        candidates: 未指定目录时，系统临时目录之后的候选目录。

    Yields:
        str: 新建的工作目录，退出时删除。

    Raises:
        RuntimeError: 指定目录或全部候选目录的可用空间不足时抛出。
    """

    if requested:
        parent = os.path.abspath(os.path.expanduser(requested))
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            raise RuntimeError(f"无法创建工作目录 {parent}: {exc}") from exc
        _require_space(parent, required_bytes)
        with _use_work_directory(parent) as work_dir:
            yield work_dir
        return

    parents = _work_dir_candidates(candidates)
    if not parents:
        raise RuntimeError(
            "未找到可写的临时工作目录，请用 --work-dir 指定空间足够的目录")
    for parent in parents:
        free = _free_space(parent)
        if (required_bytes is not None and free is not None
                and free >= required_bytes):
            with _use_work_directory(parent) as work_dir:
                yield work_dir
            return

    if required_bytes is None:
        # 无法从镜像得知解压后大小，退而选择可用空间最大的候选目录，
        # 避免默认落到容量受限的 tmpfs 上。
        parent = max(parents, key=lambda path: _free_space(path) or 0)
        with _use_work_directory(parent) as work_dir:
            yield work_dir
        return

    detail = "，".join(
        f"{parent} 可用 {_format_bytes(_free_space(parent))}"
        for parent in parents)
    raise RuntimeError(
        f"展开 squashfs 层需要约 {_format_bytes(required_bytes)} 可用空间，"
        f"候选目录均不足: {detail}。请用 --work-dir 指定空闲空间足够的目录")


def build_rootfs(
    reader: Any,
    layers: List[SquashfsLayer],
    work_dir: str,
    expected_size: Optional[int] = None,
) -> str:
    """把 squashfs 层依次展开到同一目录，得到与 overlayfs 一致的 rootfs。

    Args:
        reader: ISO 读取器，需提供 extract_file(entry, target_path)。
        layers: discover_layers 返回的层列表，底层在前。
        work_dir: 临时工作目录。
        expected_size: rootfs 解压后的字节数，用于失败时给出空间提示。

    Returns:
        str: 合并后的 rootfs 目录路径。

    Raises:
        RuntimeError: 缺少 unsquashfs 或某个层无法展开时抛出。
    """

    unsquashfs = shutil.which("unsquashfs")
    if unsquashfs is None:
        raise RuntimeError(
            "未检测到 unsquashfs（squashfs-tools），无法展开 ISO 中的 squashfs 层")

    rootfs_dir = os.path.join(work_dir, "rootfs")
    images_dir = os.path.join(work_dir, "images")
    os.makedirs(rootfs_dir, exist_ok=True)
    os.makedirs(images_dir, exist_ok=True)
    logging.info("squashfs 工作目录: %s（可用 %s）",
                 work_dir, _format_bytes(_free_space(work_dir)))

    for layer in layers:
        image_path = os.path.join(images_dir, f"layer-{layer.order}.squashfs")
        logging.info("展开 squashfs 层 %d/%d: %s",
                     layer.order, len(layers), layer.entry.display_path)
        try:
            reader.extract_file(layer.entry, image_path)
        except OSError as exc:
            raise RuntimeError(
                f"从 ISO 取出 squashfs 层 {layer.entry.display_path} 失败: {exc}"
                f"{_space_hint(work_dir, expected_size)}") from exc
        try:
            _extract_squashfs(
                unsquashfs, image_path, rootfs_dir, layer, expected_size)
        finally:
            try:
                os.remove(image_path)
            except FileNotFoundError:
                pass

    _apply_whiteouts(rootfs_dir)
    return rootfs_dir


def read_os_release(rootfs_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """读取 rootfs 中的 /etc/os-release，返回 (名称, 版本)。"""

    os_release_path = os.path.join(rootfs_dir, "etc/os-release")
    if not os.path.isfile(os_release_path):
        return None, None
    fields: Dict[str, str] = {}
    try:
        with open(os_release_path, "r", encoding="utf-8", errors="replace") as source:
            for line in source:
                if "=" not in line or line.lstrip().startswith("#"):
                    continue
                key, value = line.strip().split("=", 1)
                fields[key] = value.strip().strip('"').strip("'")
    except OSError as exc:
        logging.warning("读取 %s 失败: %s", os_release_path, exc)
        return None, None
    return (
        fields.get("NAME") or fields.get("ID"),
        fields.get("VERSION_ID") or fields.get("VERSION"),
    )


def _candidate_module_entries(entries: List[Any]) -> List[Any]:
    """返回可能描述 rootfs 层顺序的 module 文件，优先级高的在前。"""

    candidates = []
    for entry in entries:
        display_path = _display_path(entry)
        basename = posixpath.basename(display_path).casefold()
        directory = posixpath.dirname(display_path).casefold()
        if basename == MODULE_NAME:
            priority = 0
        elif basename.endswith(".module") and directory in IMAGE_DIRECTORIES:
            priority = 1
        else:
            continue
        candidates.append((priority, display_path.count("/"), display_path, entry))
    candidates.sort(key=lambda item: item[:3])
    return [item[3] for item in candidates]


def _layers_from_module(
    reader: Any,
    module_entry: Any,
    index: Dict[str, List[Any]],
    entries: List[Any],
    work_dir: str,
) -> List[SquashfsLayer]:
    """读取一个 module 文件并解析出层列表。"""

    module_path = os.path.join(work_dir, "filesystem.module")
    try:
        reader.extract_file(module_entry, module_path)
        with open(module_path, "r", encoding="utf-8", errors="replace") as source:
            listed_paths = _parse_module_lines(source.read())
    except Exception as exc:
        logging.warning("读取 %s 失败，忽略该文件: %s",
                        module_entry.display_path, exc)
        return []
    finally:
        try:
            os.remove(module_path)
        except FileNotFoundError:
            pass

    if not listed_paths:
        logging.warning("%s 未列出任何镜像", module_entry.display_path)
        return []

    layers: List[SquashfsLayer] = []
    for order, listed_path in enumerate(listed_paths, 1):
        entry = _resolve_entry(
            listed_path, module_entry, index, entries)
        if entry is None:
            logging.warning(
                "%s 中声明的镜像 %s 在 ISO 中不存在，已跳过",
                module_entry.display_path, listed_path)
            continue
        if not _display_path(entry).casefold().endswith(SQUASHFS_SUFFIX):
            logging.warning(
                "%s 中声明的镜像 %s 不是 squashfs，已跳过",
                module_entry.display_path, listed_path)
            continue
        layers.append(SquashfsLayer(entry, listed_path, order))
    return layers


def _parse_module_lines(content: str) -> List[str]:
    """按 live-boot 语义解析 module 文件：空白行和 # 注释被忽略。"""

    listed = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        listed.append(line)
    return listed


def _resolve_entry(
    listed_path: str,
    module_entry: Any,
    index: Dict[str, List[Any]],
    entries: List[Any],
) -> Optional[Any]:
    """在 ISO 条目中定位 module 里声明的镜像。"""

    normalized = listed_path.replace("\\", "/").lstrip("/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized:
        return None

    module_dir = posixpath.dirname(_display_path(module_entry))
    candidates = []
    if module_dir and not normalized.startswith(module_dir + "/"):
        candidates.append(f"{module_dir}/{normalized}")
    candidates.append(normalized)

    for candidate in candidates:
        matches = index.get(candidate.casefold())
        if matches:
            return _prefer_exact(matches, candidate)

    basename = posixpath.basename(normalized).casefold()
    matches = [
        entry for entry in entries
        if posixpath.basename(_display_path(entry)).casefold() == basename
        and _display_path(entry).casefold().endswith(SQUASHFS_SUFFIX)
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _prefer_exact(matches: List[Any], candidate: str) -> Any:
    """同一路径出现多个表示（不同 path_type）时优先大小写完全一致的条目。"""

    for entry in matches:
        if _display_path(entry) == candidate:
            return entry
    return matches[0]


def _build_path_index(entries: List[Any]) -> Dict[str, List[Any]]:
    """按大小写无关的显示路径索引 ISO 条目。"""

    index: Dict[str, List[Any]] = {}
    for entry in entries:
        index.setdefault(_display_path(entry).casefold(), []).append(entry)
    return index


def _fallback_entries(entries: List[Any]) -> List[Any]:
    """无 module 文件时，按 live-boot 的默认字典序收集 live/casper 目录下的层。"""

    candidates = []
    for entry in entries:
        display_path = _display_path(entry)
        if not display_path.casefold().endswith(SQUASHFS_SUFFIX):
            continue
        directory = posixpath.dirname(display_path).casefold()
        if directory in IMAGE_DIRECTORIES:
            candidates.append(entry)
    candidates.sort(key=_display_path)
    return candidates


def _extract_squashfs(
    unsquashfs: str,
    image_path: str,
    rootfs_dir: str,
    layer: SquashfsLayer,
    expected_size: Optional[int] = None,
) -> None:
    """把单个 squashfs 镜像展开到 rootfs，并检查非致命错误。"""

    command = [
        unsquashfs, "-f", "-no-progress", "-no-xattrs",
        "-d", rootfs_dir, image_path,
    ]
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, text=True)
    except OSError as exc:
        raise RuntimeError(
            f"执行 unsquashfs 展开层 {layer.entry.display_path} 失败: {exc}") from exc

    if result.returncode == 1:
        detail = _last_output_line(result.stderr or result.stdout)
        raise RuntimeError(
            f"展开 squashfs 层 {layer.entry.display_path} 失败: {detail}"
            f"{_space_hint(rootfs_dir, expected_size)}")
    if result.returncode == 2:
        logging.warning(
            "展开 squashfs 层 %s 时出现非致命错误（已继续）: %s",
            layer.entry.display_path, _last_output_line(result.stderr))


def _space_hint(path: str, expected_size: Optional[int] = None) -> str:
    """写入失败后，若所在分区已被写满则给出可操作的空间提示。"""

    free = _free_space(path)
    if free is None or free >= LOW_SPACE_BYTES:
        return ""
    required = required_work_space(expected_size)
    requirement = (
        f"该 rootfs 解压后约需 {_format_bytes(required)}" if required
        else "多层 live 镜像解压后的 rootfs 可达数十 GB")
    return (
        f"；写满设备的根因是磁盘空间不足（{os.path.dirname(path)} 所在分区"
        f"仅剩 {_format_bytes(free)}）。{requirement}，"
        f"请用 --work-dir 指定空闲空间足够的目录"
        f"（/tmp 常为 tmpfs，容量受内存限制）")


def _work_dir_candidates(candidates: Iterable[str]) -> List[str]:
    """按优先级返回可用的工作目录父目录，去掉重复与不可写项。"""

    ordered = [tempfile.gettempdir()]
    ordered.extend(candidates)
    result: List[str] = []
    seen = set()
    for candidate in ordered:
        if not candidate:
            continue
        path = os.path.abspath(os.path.expanduser(candidate))
        if path in seen:
            continue
        seen.add(path)
        if not os.path.isdir(path) or not os.access(path, os.W_OK):
            logging.debug("跳过不可用的工作目录候选: %s", path)
            continue
        result.append(path)
    return result


def _require_space(parent: str, required_bytes: Optional[int]) -> None:
    """校验指定工作目录的可用空间。"""

    if required_bytes is None:
        return
    free = _free_space(parent)
    if free is None or free >= required_bytes:
        return
    raise RuntimeError(
        f"工作目录 {parent} 可用 {_format_bytes(free)}，"
        f"展开该 ISO 的 squashfs 层需要约 {_format_bytes(required_bytes)}"
        f"（依据 live/filesystem.size），请用 --work-dir 指定空间足够的目录")


@contextmanager
def _use_work_directory(parent: str) -> Iterator[str]:
    """在 parent 下创建临时工作目录，退出时删除。"""

    try:
        work_dir = tempfile.mkdtemp(prefix=WORK_DIR_PREFIX, dir=parent)
    except OSError as exc:
        raise RuntimeError(f"无法在工作目录 {parent} 下创建临时目录: {exc}") from exc
    try:
        yield work_dir
    finally:
        try:
            shutil.rmtree(work_dir)
        except OSError as exc:
            logging.warning("清理工作目录 %s 失败: %s", work_dir, exc)


def _candidate_size_entries(entries: List[Any]) -> List[Any]:
    """返回可能记录 rootfs 解压后大小的文件，优先级高的在前。"""

    candidates = []
    for entry in entries:
        display_path = _display_path(entry)
        if posixpath.basename(display_path).casefold() != SIZE_HINT_NAME:
            continue
        directory = posixpath.dirname(display_path).casefold()
        priority = 0 if directory in IMAGE_DIRECTORIES else 1
        candidates.append(
            (priority, display_path.count("/"), display_path, entry))
    candidates.sort(key=lambda item: item[:3])
    return [item[3] for item in candidates]


def _free_space(path: str) -> Optional[int]:
    """返回路径所在分区的可用字节数，无法获取时返回 None。"""

    target = path
    while target and not os.path.exists(target):
        parent = os.path.dirname(target)
        if parent == target:
            break
        target = parent
    try:
        return shutil.disk_usage(target or ".").free
    except OSError:
        return None


def _format_bytes(value: Optional[int]) -> str:
    """把字节数格式化为便于阅读的单位。"""

    if value is None:
        return "未知"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TiB"


def _last_output_line(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-1] if lines else "未知错误"


def _apply_whiteouts(rootfs_dir: str) -> None:
    """应用 overlayfs 的 whiteout 语义，删除被上层隐藏的下层文件。"""

    for directory, _, file_names in os.walk(rootfs_dir, topdown=False):
        if WHITEOUT_OPAQUE in file_names:
            logging.warning(
                "检测到 overlay 不透明目录标记 %s，下层同名目录内容无法完全还原",
                os.path.join(directory, WHITEOUT_OPAQUE))
        for file_name in file_names:
            if not file_name.startswith(WHITEOUT_PREFIX):
                continue
            marker = os.path.join(directory, file_name)
            if file_name == WHITEOUT_OPAQUE:
                os.remove(marker)
                continue
            target = os.path.join(directory, file_name[len(WHITEOUT_PREFIX):])
            try:
                if os.path.islink(target) or not os.path.isdir(target):
                    if os.path.lexists(target):
                        os.remove(target)
                else:
                    shutil.rmtree(target)
            except OSError as exc:
                logging.warning("应用 whiteout %s 失败: %s", marker, exc)
            try:
                os.remove(marker)
            except OSError as exc:
                logging.warning("删除 whiteout 标记 %s 失败: %s", marker, exc)


def _display_path(entry: Any) -> str:
    return str(entry.display_path).replace("\\", "/").lstrip("/")
