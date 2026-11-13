# XiLing SBOM Tool User Manual

## Overview

The XiLing SBOM Tool is designed to scan ISO images, Docker images, software packages (`.rpm` / `.deb` / `.src.rpm` / source archives / `.dsc` files), or software repository URLs. It generates Software Bill of Materials (SBOM) manifests in explicitly requested Linx, SPDX 2.2, SPDX 2.3, SPDX 3.0, and SBOMDF (GB/T 47020-2026) formats. This manual applies to version 1.1.1. Delivered as a containerized application, the tool can be run with a single command via Docker Compose, eliminating the need for manual dependency management and environment configuration.

## System Requirements

| Item | Minimum Requirements | Recommended Requirements |
| --- | --- | --- |
| Docker | 18.09.1+ | 20.10+ |
| Docker Compose | 1.27.0+ | 2.0+ |
| RAM | 4 GB | 8 GB |
| Disk Space | 20 GB (Including temporary ISO parsing files and output files) | 40 GB (multi-squashfs live ISO) |

> **Additional Requirements**: ISO scans parse the image file system directly and do not require FUSE, `mount`, or extra container mount privileges, nor root or fakeroot: when `unsquashfs` runs as a normal user it only skips device nodes and file ownership, which does not affect package and file inventory. Multi-squashfs live ISOs require `unsquashfs` (`squashfs-tools`), and the work directory must hold all extracted layers.

## Image Acquisition and Loading

Run the following commands from the extracted `linx-xiling-dist` directory:

```bash
docker load -i image/linx-xiling_1.1.1.tar
docker images | grep linx-xiling      # Verify loading
```

## Quick Start

Before running any scan tasks, please ensure you are in the directory containing the `docker-compose.yml` file. All scan tasks are executed using the following standard format:

```bash
docker compose run --rm linx-xiling [options]
```

---

## Scan Modes in Detail

The tool provides four scanning modes. You must select one, and only one, mode per run. Place local scan targets in the directory containing `docker-compose.yml`; they are available inside the container under `/app/data`. Results written to `/app/output` are saved in the host `output/` directory.

### 1. ISO Image Scan (`--iso` / `-i`)

Performs a complete scan of a local ISO image file, extracts information for all software packages within it, and generates an SBOM.

For live images such as UOS and Deepin, the image content may be split across multiple squashfs files. The ISO's `filesystem.module` file (usually under `/live` or `/casper`) lists those squashfs files from the bottom layer to the top layer, and the boot process unions them with overlayfs into the final rootfs. The tool reads that file and extracts every layer into the same temporary directory in the same order (later layers overwrite earlier ones), then enumerates installed packages from the merged rootfs's dpkg or RPM database. When `filesystem.module` is absent, squashfs files under `live`/`casper` are layered in default filename order.

This mode requires `unsquashfs` (`squashfs-tools`). The extracted layers can be much larger than the ISO itself (the UOS Desktop 25 rootfs is about 25 GB uncompressed), so the work directory must live on real disk: `/tmp` is often a tmpfs limited by RAM, and when it fills up `unsquashfs` only reports `FATAL ERROR: writer: failed to write file ...`.

The work directory is selected as follows:

1. the directory given with `--work-dir` (or `scan.work_dir` in the configuration file);
2. otherwise the first of the system temporary directory (`TMPDIR`), the ISO's directory and the current directory that has enough free space; the chosen path is logged;
3. when the ISO contains `live/filesystem.size` (the uncompressed rootfs size recorded by live-boot), free space is validated against it before extraction starts, so an undersized directory fails in seconds with the required size instead of after a full extraction.

```bash
xlin-sbom -i ~/Public/ISO/uos-desktop-25-professional-2500-amd64-202607.iso \
          -o ~/sbom --format spdx23 --work-dir /data/tmp
```

**Command Format**:

```bash
docker compose run --rm linx-xiling -i /app/data/<image_file.iso> -o /app/output --format linx --format spdx
```

**Example**:

```bash
docker compose run --rm linx-xiling -i /app/data/centos-8-stream.iso -o /app/output --format linx --format spdx
```

### 2. Software Package Scan (`--package` / `-p`)

Scans a single software package file and generates its SBOM manifest. Supported inputs include binary packages (`.rpm`, `.deb`), RPM source packages (`.src.rpm`), source archives (`.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.tar`, `.zip`), and Debian source description files (`.dsc`).

**Command Format**:

```bash
docker compose run --rm linx-xiling -p /app/data/<package_file> -o /app/output --format linx --format spdx
```

**Example**:

```bash
docker compose run --rm linx-xiling -p /app/data/zvbi-0.2.35-8.oe2203sp4.src.rpm -o /app/output --format linx --format spdx
```

Source archives are unpacked safely for file-level license scanning. The bundled OSV Scanner also detects dependencies from common ecosystem manifest files. If no supported dependency manifest is present, or the runtime cannot reach the online OSV service, dependency results may be empty while package, file, and license SBOM output is still generated. Source file-level scanning reads `source_scan.include_file_patterns` from the configuration file by default, so only common source files and license/copyright notices are scanned unless you adjust `./config/config.json`.

### 3. Docker Image Scan (`--docker` / `-d`)

Scans a public Docker Hub image or an offline Docker image tar archive. The scanner analyzes the final image filesystem, reads dpkg or RPM package databases, and generates Linx, SPDX, or SBOMDF (GB/T 47020-2026) SBOM output.

**Docker Hub image**:

```bash
docker compose run --rm linx-xiling -d debian:bookworm-slim -o /app/output --format linx --format spdx
```

For multi-platform images, the platform is controlled by `scan.platform` in the configuration file. The default value is `linux/amd64`.

**Offline image tar**:

```bash
docker compose run --rm linx-xiling -d /app/data/linx-xiling_1.1.1.tar -o /app/output --format linx --format spdx
```

Docker image scanning depends on installed package databases in the final filesystem. Images without dpkg or RPM databases, such as scratch or some distroless images, cannot produce system package SBOMs in this version.

RPM database detection supports SQLite (`rpmdb.sqlite`), BDB (`Packages`), and NDB v0 (`Packages.db`) under `/var/lib/rpm` or `/usr/lib/sysimage/rpm`. NDB records are validated and imported into a separate SQLite database in the scan temporary directory before querying; the input image is unchanged.

### 4. Repository Scan (`--repo` / `-r`)

Scans a specified YUM/DNF or APT repository URL, parses repository metadata, and generates a package-level SBOM. Repository metadata generally provides package and license information, but does not reliably provide file-level information or package dependencies.

Repository metadata does not provide reliable software-level information, so repository scans do not support `--format sbomdf`.

**Command Format**:

```bash
docker compose run --rm linx-xiling -r <repository_URL> -o /app/output --format linx --format spdx
```

**Example**:

```bash
docker compose run --rm linx-xiling -r https://mirrors.example.com/centos/8-stream/BaseOS/x86_64/os/ -o /app/output --format linx --format spdx
```

---

## Optional Parameters

In addition to the required scan mode and output parameters, the CLI keeps the following arguments:

| Parameter | Description |
| --- | --- |
| `--help`, `-h` | Show help message and exit |
| `--format {linx,spdx,spdx22,spdx23,spdx3,sbomdf}` | Required output format; can be repeated. `spdx` and `spdx23` are SPDX 2.3 aliases |
| `--ecosystem <ecosystem>` | OSV ecosystem for SBOMDF vulnerability queries; required for inputs other than source archives, and optional as a fallback for source archives |
| `--work-dir <dir>` | Work directory for expanding squashfs layers during ISO scans; it needs free space at least the size of the extracted rootfs. Defaults to the first of `TMPDIR`, the ISO's directory and the current directory that has enough space; can be pinned with `scan.work_dir` in the configuration file |

Supported formats: `linx`, `spdx22` (SPDX 2.2), `spdx`/`spdx23` (SPDX 2.3), `spdx3` (SPDX 3.0 JSON-LD), `sbomdf` (GB/T 47020-2026).

SBOMDF (GB/T 47020-2026) output example:

```bash
docker compose run --rm linx-xiling -p /app/data/example.rpm -o /app/output --format sbomdf --ecosystem PyPI
```

SBOMDF output queries vulnerabilities from the local OSV Elasticsearch database. For inputs other than tar/zip source archives, specify the matching OSV ecosystem with `--ecosystem`. Source archives use each component's ecosystem detected by OSV Scanner; the supplied `--ecosystem` is used only as a fallback when that information is unavailable. Available ecosystems can be listed in the companion XiLing SBOM analysis environment with `docker compose run --rm es-manager list-ecosystems`.

Linx output is a directory containing JSON files for packages, files, licenses, and their relationships. SPDX 2.2 and 2.3 output is JSON; SPDX 3.0 output is JSON-LD. The generated SBOMDF directory contains `*.SBOMDF.json`, `signature.sig`, and `certification.pem`.

---

## Configuration File

The bundled default configuration file is `/app/assist/config.json`. Docker Compose mounts the host `./config` directory to `/app/config`, and the tool automatically reads `/app/config/config.json` as the external configuration file.

Users only need to edit `./config/config.json` on the host. If this external configuration file is missing, the scanner uses the bundled default configuration. If the external file contains invalid JSON, unknown options, or invalid field types/values, the scanner logs a Chinese warning and falls back to the bundled default value for the affected field. `/app/assist/config.json` is the required default configuration file; if it is missing or invalid, the image or project files are considered broken and the scanner exits with an error.

Configuration options:

```json
{
    "scan": {
        "disable_tqdm": false,
        "max_workers": null,
        "platform": "linux/amd64",
        "work_dir": null
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

| Option | Description |
| --- | --- |
| `scan.disable_tqdm` | Disable progress bar display |
| `scan.max_workers` | Maximum number of concurrent workers; `null` keeps the program default |
| `scan.platform` | Docker image platform, such as `linux/amd64` or `linux/arm64` |
| `scan.work_dir` | Work directory for expanding squashfs layers during ISO scans; `null` auto-selects the first of `TMPDIR`, the ISO's directory and the current directory with enough space, while `--work-dir` on the command line takes precedence |
| `source_scan.include_file_patterns` | Include patterns for source package file-level scans |
| `source_scan.exclude_file_patterns` | Exclude patterns for source package file-level scans |
| `source_scan.brief` | Skip file-level license scanning and OSV dependency detection for source packages |
| `elastic_search.hosts` | Local OSV Elasticsearch node URLs |
| `elastic_search.index_name` | OSV vulnerability index name |
| `elastic_search.api_key` | Elasticsearch API key, blank by default; set it in the external configuration when authentication is required |
| `elastic_search.verify_certs` | Verify the Elasticsearch HTTPS certificate; defaults to `true`. A controlled intranet without an available trusted CA may explicitly set it to `false` |
| `elastic_search.ca_certs` | CA certificate path inside the container; used only when certificate verification is enabled and the value is non-empty |

When `verify_certs` is `true` and `ca_certs` is empty, the tool uses the runtime's default CA bundle. When `ca_certs` is set, that file is used. Setting `verify_certs` to `false` skips certificate verification and should only be used in a controlled intranet because the Elasticsearch server identity is no longer authenticated.

## Runtime Data Locations (installed packages)

When installed from the deb/rpm package, the program directory `/usr/share/xlin-sbom` is treated as read-only data. Logs are written to `${XDG_STATE_HOME:-$HOME/.local/state}/xlin-sbom/log` (override with `XLIN_SBOM_LOG_DIR`), and the accumulated originators cache is written to `${XDG_CACHE_HOME:-$HOME/.cache}/xlin-sbom/originators.json` (override with `XLIN_SBOM_CACHE_DIR`). The bundled `/usr/share/xlin-sbom/assist/originators.json` is only used as the read-only seed for the first scan; the tool never writes into the installation directory.

## Troubleshooting

### 1. `docker compose` Execution Error or Parsing Failure

* **Symptom**: Prompts `docker: 'compose' is not a docker command` or `The Compose file is invalid`.
* **Solution**:
* If your system only supports Docker Compose V1, replace `docker compose` with `docker-compose` in your commands.

### 2. Network Connection Failure During Repository Scan

* **Cause**: Incorrect DNS or proxy configuration within the container, or the repository URL is unreachable.
* **Solution**:
* Check if the host machine can access the URL.
* Add `network_mode: host` to the service in `docker-compose.yml` or configure DNS (`dns: 8.8.8.8`).
* If a proxy is required, set the `HTTP_PROXY` / `HTTPS_PROXY` environment variables.

### 3. No Files Generated in the Output Directory

* **Cause**: The `./output` directory on the host does not exist or lacks write permissions.
* **Solution**: Manually create the directory and grant permissions:

```bash
mkdir -p ./output
chmod 755 ./output
```

### 4. Docker Hub Image Pull Failure

The current version supports anonymous pulls for public Docker Hub images only. Check network access to Docker Hub. Private images, authenticated images, and non-Docker-Hub registry addresses return a clear error message.

### 5. Docker Image Package System Not Detected

Docker image scanning requires `/var/lib/dpkg/status` or an RPM database in the final image filesystem. Images built from scratch, distroless images, or images that remove package manager metadata cannot be scanned as OS package images in this version.

---

*XiLing SBOM Tool — Making software supply chain assets clear at a glance.*
