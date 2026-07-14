# 析灵 SBOM 生成工具用户手册

## 概述

析灵 SBOM 生成工具用于扫描 ISO 镜像、Docker 镜像、单个软件包（`.rpm`、`.deb`、`.src.rpm`、源码压缩包、Debian 源码描述文件）或软件更新源 URL，并生成软件物料清单（Software Bill of Materials，SBOM）。

工具支持输出 Linx 格式、SPDX 2.3 格式和 GB/T 47020-2026 格式的 SBOM 清单。运行时必须通过 `--format` 参数显式指定一种或多种输出格式。

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
docker compose run --rm linx-xiling -i /app/data/<镜像文件.iso> -o /app/output --format linx --format spdx
```

### 2. 单个软件包扫描（`--package` / `-p`）

扫描单个软件包文件。当前支持：

- 二进制包：`.rpm`、`.deb`
- RPM 源码包：`.src.rpm`
- 源码归档：`.tar.gz`、`.tgz`、`.tar.bz2`、`.tar.xz`、`.tar`、`.zip`
- Debian 源码描述文件：`.dsc`

```bash
docker compose run --rm linx-xiling -p /app/data/<软件包文件> -o /app/output --format linx --format spdx
```

源码包在 v1.1.0 中已经拆分为独立处理策略。其中 `.src.rpm` 会继续使用 RPM spec 信息并支持源码文件级扫描；tar、zip 源码归档会安全解压后进行文件级许可证扫描，并通过内置 OSV Scanner 识别常见语言生态的依赖信息。生成 GBT 格式时，源码归档依赖会优先使用 OSV Scanner 结果中每个组件自己的 ecosystem 查询漏洞，`--ecosystem` 仅作为缺少组件生态系统时的兜底值。若源码归档中缺少依赖清单文件，或运行环境无法访问 OSV 在线服务，依赖结果可能为空，但工具仍会保留可获取的包级、文件级和许可证 SBOM。Debian `.dsc` 会生成可从描述文件中获取的包级 SBOM。

源码文件级扫描默认读取配置文件中的 `source_scan.include_file_patterns`，仅扫描常见源码文件和许可证/版权声明文件。用户可修改宿主机上的 `./config/config.json` 调整 include、exclude、线程数、进度条和源码扫描精简模式等运行参数。

### 3. Docker 镜像扫描（`--docker` / `-d`）

扫描 Docker Hub 公共镜像或离线 Docker 镜像 tar 文件，识别镜像最终文件系统中的 dpkg 或 RPM 包数据库，并生成 Linx 与 SPDX SBOM。

在线镜像扫描默认从 Docker Hub 拉取公共镜像，默认平台为 `linux/amd64`：

```bash
docker compose run --rm linx-xiling -d debian:bookworm-slim -o /app/output --format linx --format spdx
```

多架构镜像的平台默认由配置文件中的 `scan.platform` 控制，默认值为 `linux/amd64`。

离线镜像扫描直接传入 `.tar` 文件路径：

```bash
docker compose run --rm linx-xiling -d /app/data/linx-xiling_1.0.0.tar -o /app/output --format linx --format spdx
```

Docker 镜像扫描对象是已安装的系统包数据库；如果镜像内没有 dpkg 或 RPM 数据库，工具会给出中文错误提示。

### 4. 软件源扫描（`--repo` / `-r`）

扫描指定的 YUM/DNF 或 APT 软件源 URL，解析仓库元数据并生成包级 SBOM。

```bash
docker compose run --rm linx-xiling -r https://mirrors.example.com/centos/8-stream/BaseOS/x86_64/os/ -o /app/output --format linx --format spdx
```

软件源元数据通常只能提供包和许可证等包级信息，无法可靠提供包内文件、文件关系和包间依赖关系，因此 repo 扫描仅输出可从仓库元数据获取的清单内容。由于 GB/T 47020-2026 格式需要软件信息，repo 扫描不支持 `--format gbt`。

## 输出格式

输出格式必须显式指定。例如同时输出 Linx 和 SPDX：

```bash
docker compose run --rm linx-xiling -p /app/data/example.rpm -o /app/output --format linx --format spdx
```

仅输出 SPDX：

```bash
docker compose run --rm linx-xiling -p /app/data/example.rpm -o /app/output --format spdx
```

显式同时输出 Linx 和 SPDX：

```bash
docker compose run --rm linx-xiling -p /app/data/example.rpm -o /app/output --format linx --format spdx
```

输出 GB/T 47020-2026 格式：

```bash
docker compose run --rm linx-xiling -p /app/data/example.rpm -o /app/output --format gbt --ecosystem PyPI
```

生成 GBT 格式时，除 tar、zip 等源码归档外，必须通过 `--ecosystem` 指定 OSV 生态系统，用于从本地 Elasticsearch 漏洞库查询安全漏洞。源码归档可以省略该参数，工具会优先使用 OSV Scanner 输出的组件 ecosystem；若用户同时提供 `--ecosystem`，仅在组件缺少 ecosystem 时作为兜底值。可用生态系统可在析灵 SBOM 分析工具本地环境中通过 `docker compose run --rm es-manager list-ecosystems` 查看。

Linx 格式会输出到一个目录中，并按清单类型拆分为 `packages`、`files`、`licenses`、`package_relationships`、`file_relationships` 等 JSON 文件。SPDX 格式会输出为一个 SPDX 2.3 JSON 文件。GBT 格式会输出到独立目录，目录中包含 `*.SBOMDF.json`、`signature.sig` 和 `certification.pem`。

## 可选参数

| 参数 | 说明 |
| --- | --- |
| `--help`, `-h` | 显示帮助信息并退出 |
| `--format {linx,spdx,gbt}` | 必填。指定输出格式，可重复指定 |
| `--ecosystem <生态系统>` | 生成 GBT 格式时用于 OSV/Elasticsearch 漏洞查询；源码归档可省略，其他扫描对象必填 |

## 配置文件

镜像内默认配置文件为 `/app/assist/config.json`。Docker Compose 会将宿主机 `./config` 目录挂载到容器 `/app/config`，工具启动时会自动读取 `/app/config/config.json` 作为外部配置。

用户只需要修改宿主机上的 `./config/config.json`。如果该外部配置文件不存在，工具会使用镜像内默认配置；如果外部配置 JSON 格式错误、存在未知配置项或某个字段类型/取值错误，工具会记录中文警告，并对错误字段使用镜像内默认配置，不会因为单个错误配置项中断扫描。`/app/assist/config.json` 是必需的默认配置文件，如果该文件缺失或内容不合法，说明镜像或项目文件损坏，工具会直接报错退出。

配置项如下：

```json
{
    "scan": {
        "disable_tqdm": false,
        "max_workers": null,
        "platform": "linux/amd64"
    },
    "source_scan": {
        "include_file_patterns": ["*.py", "*.js", "*LICENSE*"],
        "exclude_file_patterns": [],
        "brief": false
    },
    "elastic_search": {
        "hosts": [
            "http://host.docker.internal:9200"
        ],
        "index_name": "osv_vulnerability_db",
        "api_key": "",
        "verify_certs": true,
        "ca_certs": ""
    }
}
```

| 配置项 | 说明 |
| --- | --- |
| `scan.disable_tqdm` | 是否禁用进度条显示 |
| `scan.max_workers` | 最大并发线程数或进程数；`null` 表示使用程序默认策略 |
| `scan.platform` | Docker 多架构镜像平台，例如 `linux/amd64`、`linux/arm64` |
| `source_scan.include_file_patterns` | 源码包文件级扫描包含模式 |
| `source_scan.exclude_file_patterns` | 源码包文件级扫描排除模式 |
| `source_scan.brief` | 源码包扫描时是否跳过文件级许可证扫描和 OSV 依赖识别 |
| `elastic_search.hosts` | 本地 OSV Elasticsearch 节点地址列表 |
| `elastic_search.index_name` | OSV 漏洞索引名称 |
| `elastic_search.api_key` | Elasticsearch API Key，默认留空；需要认证时在外部配置中填写 |
| `elastic_search.verify_certs` | 是否校验 Elasticsearch HTTPS 证书，默认为 `true`；无法提供可信 CA 的受控内网环境可显式设为 `false` |
| `elastic_search.ca_certs` | Elasticsearch HTTPS CA 证书在容器内的路径；仅在启用证书校验且该值非空时使用 |

当 `verify_certs` 为 `true` 且 `ca_certs` 为空时，工具使用运行环境的默认 CA 校验证书；指定 `ca_certs` 时使用该文件；设为 `false` 时跳过证书校验。关闭证书校验会失去 Elasticsearch 服务端身份验证能力，应仅用于网络边界明确的受控内网环境。

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

### 4. Docker Hub 镜像拉取失败

请确认当前网络可以访问 Docker Hub。当前版本仅支持匿名拉取公共 Docker Hub 镜像；私有镜像、需要登录的镜像或其他镜像仓库地址会返回中文错误提示。

### 5. Docker 镜像无法识别包系统

Docker 镜像扫描依赖镜像最终文件系统中的 `/var/lib/dpkg/status` 或 RPM 数据库。如果镜像是 scratch、distroless 或不包含包管理数据库，当前版本无法生成系统包级 SBOM。

---

析灵 SBOM 生成工具，让软件供应链资产一目了然。
