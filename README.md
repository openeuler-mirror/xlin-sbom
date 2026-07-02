# 析灵 SBOM 生成工具用户手册

## 概述

析灵 SBOM 生成工具用于扫描 ISO 镜像、单个软件包（`.rpm`、`.deb`、`.src.rpm`、源码压缩包、Debian 源码描述文件）或软件更新源 URL，并生成软件物料清单（Software Bill of Materials，SBOM）。

工具支持输出 Linx 格式和 SPDX 2.3 格式的 SBOM 清单。运行时可以通过 `--format` 参数指定一种或多种输出格式；如果不指定，则默认同时输出 Linx 和 SPDX 两种格式。

项目以容器化方式交付，可通过 Docker Compose 运行，避免手动配置运行环境。

## 系统要求

| 项目 | 最低配置 | 推荐配置 |
| --- | --- | --- |
| Docker | 18.09.1+ | 20.10+ |
| Docker Compose | 1.27.0+ | 2.0+ |
| 内存 | 4 GB | 8 GB |
| 磁盘空间 | 10 GB（含 ISO 临时解析文件及输出文件） | 20 GB |

> ISO 扫描会直接解析镜像文件系统，不依赖 FUSE、`mount` 或额外的容器挂载权限。

## 镜像获取与加载

```bash
docker load -i linx-xiling-1.1.0.tar
docker images | grep linx-xiling
```

## 快速开始

请在包含 `docker-compose.yml` 的目录下执行扫描命令：

```bash
docker compose run --rm linx-xiling [参数]
```

## 扫描模式

每次运行必须且只能选择一种扫描模式。

### 1. ISO 镜像扫描（`--iso` / `-i`）

扫描本地 ISO 镜像，识别其中的 RPM 或 DEB 软件包，并生成 SBOM。

```bash
docker compose run --rm linx-xiling -i /app/data/<镜像文件.iso> -o /app/output
```

### 2. 单个软件包扫描（`--package` / `-p`）

扫描单个软件包文件。当前支持：

- 二进制包：`.rpm`、`.deb`
- RPM 源码包：`.src.rpm`
- 源码归档：`.tar.gz`、`.tgz`、`.tar.bz2`、`.tar.xz`、`.tar`、`.zip`
- Debian 源码描述文件：`.dsc`

```bash
docker compose run --rm linx-xiling -p /app/data/<软件包文件> -o /app/output
```

源码包在 v1.1.0 中已经拆分为独立处理策略。其中 `.src.rpm` 会继续使用 RPM spec 信息并支持源码文件级扫描；tar、zip、Debian source 会生成基础包级 SBOM，文件级许可证扫描将在后续版本完善。

### 3. 软件源扫描（`--repo` / `-r`）

扫描指定的 YUM/DNF 或 APT 软件源 URL，解析仓库元数据并生成包级 SBOM。

```bash
docker compose run --rm linx-xiling -r https://mirrors.example.com/centos/8-stream/BaseOS/x86_64/os/ -o /app/output
```

软件源元数据通常只能提供包和许可证等包级信息，无法可靠提供包内文件、文件关系和包间依赖关系，因此 repo 扫描仅输出可从仓库元数据获取的清单内容。

## 输出格式

默认同时输出 Linx 和 SPDX：

```bash
docker compose run --rm linx-xiling -p /app/data/example.rpm -o /app/output
```

仅输出 SPDX：

```bash
docker compose run --rm linx-xiling -p /app/data/example.rpm -o /app/output --format spdx
```

显式同时输出 Linx 和 SPDX：

```bash
docker compose run --rm linx-xiling -p /app/data/example.rpm -o /app/output --format linx --format spdx
```

Linx 格式会输出到一个目录中，并按清单类型拆分为 `packages`、`files`、`licenses`、`package_relationships`、`file_relationships` 等 JSON 文件。SPDX 格式会输出为一个 SPDX 2.3 JSON 文件。

## 可选参数

| 参数 | 说明 |
| --- | --- |
| `--help`, `-h` | 显示帮助信息并退出 |
| `--disable-tqdm` | 禁用进度条显示，适合日志记录环境 |
| `--max-workers MAX_WORKERS` | 最大并发线程数或进程数 |
| `--include PATTERN` | 源码包文件级扫描时要包含的文件模式，可重复指定 |
| `--exclude PATTERN` | 源码包文件级扫描时要排除的文件模式，可重复指定 |
| `--brief` | 源码包扫描时仅生成包级信息，跳过文件级扫描 |
| `--format {linx,spdx}` | 指定输出格式，可重复指定；默认同时输出 Linx 和 SPDX |

## 故障排除

### 1. `docker compose` 执行错误或解析失败

如果系统提示 `docker: 'compose' is not a docker command`，说明当前 Docker 环境可能只支持 Docker Compose V1。请将命令中的 `docker compose` 替换为 `docker-compose`。

### 2. 扫描软件源时网络连接失败

请检查宿主机是否可以访问目标 URL。必要时可在 `docker-compose.yml` 中配置 DNS、代理环境变量，或根据运行环境使用 `network_mode: host`。

### 3. 输出目录未生成文件

请确认宿主机上的 `./output` 目录存在并具有写入权限：

```bash
mkdir -p ./output
chmod 755 ./output
```

---

析灵 SBOM 生成工具，让软件供应链资产一目了然。
