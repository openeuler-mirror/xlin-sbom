# XiLing SBOM Tool User Manual

## Overview

The XiLing SBOM Tool is designed to scan ISO images, Docker images, software packages (`.rpm` / `.deb` / `.src.rpm` / source archives), or software repository URLs. It generates Software Bill of Materials (SBOM) manifests in explicitly requested Linx, SPDX 2.3, and GB/T 47020-2026 formats. Delivered as a containerized application, the tool can be run with a single command via Docker Compose, eliminating the need for manual dependency management and environment configuration.

## System Requirements

| Item | Minimum Requirements | Recommended Requirements |
| --- | --- | --- |
| Docker | 18.09.1+ | 20.10+ |
| Docker Compose | 1.27.0+ | 2.0+ |
| RAM | 4 GB | 8 GB |
| Disk Space | 10 GB (Including temporary ISO parsing files and output files) | 20 GB |

> **Additional Requirements**: ISO scans parse the image file system directly and do not require FUSE, `mount`, or extra container mount privileges.

## Image Acquisition and Loading

```bash
docker load -i linx-xiling-1.0.0.tar
docker images | grep linx-xiling      # Verify loading

```

## Quick Start

Before running any scan tasks, please ensure you are in the directory containing the `docker-compose.yml` file. All scan tasks are executed using the following standard format:

```bash
docker compose run --rm linx-xiling [options]

```

---

## Scan Modes in Detail

The tool provides four scanning modes. You must select one, and only one, mode per run.

### 1. ISO Image Scan (`--iso` / `-i`)

Performs a complete scan of a local ISO image file, extracts information for all software packages within it, and generates an SBOM.

**Command Format**:

```bash
docker compose run --rm linx-xiling -i /app/data/<image_file.iso> -o output/ --format linx --format spdx

```

**Example**:

```bash
docker compose run --rm linx-xiling -i /app/data/centos-8-stream.iso -o output/ --format linx --format spdx

```

### 2. Software Package Scan (`--package` / `-p`)

Scans a single software package file and generates its SBOM manifest. Supported inputs include binary packages (`.rpm`, `.deb`), RPM source packages (`.src.rpm`), source archives (`.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.tar`, `.zip`), and Debian source description files (`.dsc`).

**Command Format**:

```bash
docker compose run --rm linx-xiling -p /app/data/<package_file> -o output/ --format linx --format spdx

```

**Example**:

```bash
docker compose run --rm linx-xiling -p /app/data/zvbi-0.2.35-8.oe2203sp4.src.rpm -o output/ --format linx --format spdx

```

Source archives are unpacked safely for file-level license scanning. The bundled OSV Scanner also detects dependencies from common ecosystem manifest files. If no supported dependency manifest is present, or the runtime cannot reach the online OSV service, dependency results may be empty while package, file, and license SBOM output is still generated. Source file-level scanning reads `source_scan.include_file_patterns` from the configuration file by default, so only common source files and license/copyright notices are scanned unless you adjust `./config/config.json`.

### 3. Docker Image Scan (`--docker` / `-d`)

Scans a public Docker Hub image or an offline Docker image tar archive. The scanner analyzes the final image filesystem, reads dpkg or RPM package databases, and generates Linx, SPDX, or GBT SBOM output.

**Docker Hub image**:

```bash
docker compose run --rm linx-xiling -d debian:bookworm-slim -o output/ --format linx --format spdx

```

For multi-platform images, the platform is controlled by `scan.platform` in the configuration file. The default value is `linux/amd64`.

**Offline image tar**:

```bash
docker compose run --rm linx-xiling -d /app/data/linx-xiling_1.0.0.tar -o output/ --format linx --format spdx

```

Docker image scanning depends on installed package databases in the final filesystem. Images without dpkg or RPM databases, such as scratch or some distroless images, cannot produce system package SBOMs in this version.

### 4. Repository Scan (`--repo` / `-r`)

Scans a specified software repository URL (such as a YUM/APT repository), recursively analyzes all software packages within the repository, and generates a comprehensive SBOM.

Repository metadata does not provide reliable software-level information, so repository scans do not support `--format gbt`.

**Command Format**:

```bash
docker compose run --rm linx-xiling -r <repository_URL> -o output/ --format linx --format spdx

```

**Example**:

```bash
docker compose run --rm linx-xiling -r https://mirrors.example.com/centos/8-stream/BaseOS/x86_64/os/ -o output/ --format linx --format spdx

```

---

## Optional Parameters

In addition to the required scan mode and output parameters, the CLI keeps the following arguments:

| Parameter | Description |
| --- | --- |
| `--help`, `-h` | Show help message and exit |
| `--format {linx,spdx,gbt}` | Required output format; can be repeated |
| `--ecosystem <ecosystem>` | Required for GBT output; used for OSV/Elasticsearch vulnerability queries |

GBT output example:

```bash
docker compose run --rm linx-xiling -p /app/data/example.rpm -o /app/output --format gbt --ecosystem PyPI
```

GBT output requires `--ecosystem` so the tool can query vulnerabilities from the local OSV Elasticsearch database. The generated GBT directory contains `*.SBOMDF.json`, `signature.sig`, and `certification.pem`.

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

| Option | Description |
| --- | --- |
| `scan.disable_tqdm` | Disable progress bar display |
| `scan.max_workers` | Maximum number of concurrent workers; `null` keeps the program default |
| `scan.platform` | Docker image platform, such as `linux/amd64` or `linux/arm64` |
| `source_scan.include_file_patterns` | Include patterns for source package file-level scans |
| `source_scan.exclude_file_patterns` | Exclude patterns for source package file-level scans |
| `source_scan.brief` | Skip file-level license scanning and OSV dependency detection for source packages |
| `elastic_search.hosts` | Local OSV Elasticsearch node URLs |
| `elastic_search.index_name` | OSV vulnerability index name |
| `elastic_search.api_key` | Elasticsearch API key, blank by default; set it in the external configuration when authentication is required |
| `elastic_search.verify_certs` | Verify the Elasticsearch HTTPS certificate; defaults to `true`. A controlled intranet without an available trusted CA may explicitly set it to `false` |
| `elastic_search.ca_certs` | CA certificate path inside the container; used only when certificate verification is enabled and the value is non-empty |

When `verify_certs` is `true` and `ca_certs` is empty, the tool uses the runtime's default CA bundle. When `ca_certs` is set, that file is used. Setting `verify_certs` to `false` skips certificate verification and should only be used in a controlled intranet because the Elasticsearch server identity is no longer authenticated.

## Troubleshooting

### 1. `docker compose` Execution Error or Parsing Failure

* **Symptom**: Prompts `docker: 'compose' is not a docker command` or `The Compose file is invalid`.
* **Solution**:
* Check the `docker-compose.yml` file version. For older Docker environments, ensure the file starts with `version: '2.2'`.
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



---

*XiLing SBOM Tool — Making software supply chain assets clear at a glance.*

```

### 4. Docker Hub Image Pull Failure

The current version supports anonymous pulls for public Docker Hub images only. Check network access to Docker Hub. Private images, authenticated images, and non-Docker-Hub registry addresses return a clear error message.

### 5. Docker Image Package System Not Detected

Docker image scanning requires `/var/lib/dpkg/status` or an RPM database in the final image filesystem. Images built from scratch, distroless images, or images that remove package manager metadata cannot be scanned as OS package images in this version.
