# 析灵SBOM生成工具用户手册

## 概述

析灵SBOM生成工具用于对ISO镜像、单个软件包（.rpm / .deb / .src.rpm）或软件更新源URL进行扫描，自动生成符合凝思格式和SPDX国际标准的SBOM（Software Bill of Materials，软件物料清单）清单。工具以容器化方式交付，通过Docker Compose一键运行，无需手动处理依赖和环境配置。

## 系统要求

| 项目 | 最低配置 | 推荐配置 |
| --- | --- | --- |
| Docker | 18.09.1+ | 20.10+ |
| Docker Compose | 1.27.0+ | 2.0+ |
| 内存 | 4 GB | 8 GB |
| 磁盘空间 | 10 GB（含ISO挂载及输出文件） | 20 GB |

> **额外要求**：运行ISO扫描时，容器需要具备挂载文件系统的权限。请确保Docker宿主机内核支持FUSE。

## 镜像获取与加载

```bash
docker load -i linx-xiling-1.0.0.tar
docker images | grep linx-xiling      # 验证加载
```

## 快速开始

在运行任何扫描任务前，请确保您位于包含 `docker-compose.yml` 的目录下。所有扫描任务均通过以下固定格式执行：

```bash
docker compose run --rm linx-xiling [参数]
```

---

## 扫描模式详解

工具提供三种扫描模式，每次运行必须且只能选择一种。

### 1. ISO镜像扫描 (`--iso` / `-i`)

对本地ISO镜像文件进行完整扫描，提取其中所有软件包信息并生成SBOM。

**命令格式**：
```bash
docker compose run --rm linx-xiling -i /app/data/<镜像文件.iso> -o output/ [可选参数]
```

**示例**：
```bash
docker compose run --rm linx-xiling -i /app/data/centos-8-stream.iso -o output/
```

### 2. 软件包扫描 (`--package` / `-p`)

扫描单个软件包文件（支持 `.rpm`, `.deb`, `.src.rpm` 等格式），生成该包的SBOM清单。

**命令格式**：
```bash
docker compose run --rm linx-xiling -p /app/data/<软件包文件> -o output/ [可选参数]
```

**示例**：
```bash
docker compose run --rm linx-xiling -p /app/data/zvbi-0.2.35-8.oe2203sp4.src.rpm -o output/
```

### 3. 更新源扫描 (`--repo` / `-r`)

扫描指定的软件更新源URL（如YUM/APT仓库），递归分析仓库中所有软件包并生成完整SBOM。

**命令格式**：
```bash
docker compose run --rm linx-xiling -r <更新源URL> -o output/ [可选参数]
```

**示例**：
```bash
docker compose run --rm linx-xiling -r https://mirrors.example.com/centos/8-stream/BaseOS/x86_64/os/ -o output/
```

---

## 可选参数

除上述必选模式参数外，您还可使用以下选项调整扫描行为：

| 参数 | 说明 |
| --- | --- |
| `--help`, `-h` | 显示帮助消息并退出 |
| `--disable-tqdm` | 禁用进度条显示（适合日志记录环境） |
| `--max-workers MAX_WORKERS` | 最大并发线程数，默认为CPU核心数 |
| `--sbom SBOM` | 指定已存在的SBOM文件（JSON格式）进行增量更新，避免重复解析 |

---

## 故障排除

### 1. 执行 `docker compose` 报错或解析失败

- **现象**：提示 `docker: 'compose' is not a docker command` 或 `The Compose file is invalid`。  
- **解决方法**：
  - 检查 `docker-compose.yml` 文件版本。对于较老版本的Docker环境，请确保文件开头包含 `version: '2.2'`。
  - 若系统仅支持Docker Compose V1，请将命令中的 `docker compose` 替换为 `docker-compose`。

### 2. 扫描更新源时网络连接失败

- **原因**：容器内DNS或代理配置不正确，或更新源URL不可达。  
- **解决方法**：
  - 检查宿主机能否访问该URL。
  - 在 `docker-compose.yml` 中为服务添加 `network_mode: host` 或配置DNS (`dns: 8.8.8.8`)。
  - 若需使用代理，设置环境变量 `HTTP_PROXY` / `HTTPS_PROXY`。

### 3. 输出目录未生成文件

- **原因**：主机 `./output` 目录不存在或无写入权限。  
- **解决方法**：手动创建目录并赋予权限：
  ```bash
  mkdir -p ./output
  chmod 755 ./output
  ```

---

*析灵SBOM生成工具 —— 让软件供应链资产一目了然*