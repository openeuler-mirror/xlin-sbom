# XiLing SBOM Tool User Manual

## Overview

The XiLing SBOM Tool is designed to scan ISO images, software packages (`.rpm` / `.deb` / `.src.rpm`), or software repository URLs. It automatically generates Software Bill of Materials (SBOM) manifests that comply with both the Linx format and the international SPDX standard. Delivered as a containerized application, the tool can be run with a single command via Docker Compose, eliminating the need for manual dependency management and environment configuration.

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

The tool provides three scanning modes. You must select one, and only one, mode per run.

### 1. ISO Image Scan (`--iso` / `-i`)

Performs a complete scan of a local ISO image file, extracts information for all software packages within it, and generates an SBOM.

**Command Format**:

```bash
docker compose run --rm linx-xiling -i /app/data/<image_file.iso> -o output/ [optional parameters]

```

**Example**:

```bash
docker compose run --rm linx-xiling -i /app/data/centos-8-stream.iso -o output/

```

### 2. Software Package Scan (`--package` / `-p`)

Scans a single software package file (supports formats like `.rpm`, `.deb`, `.src.rpm`, etc.) and generates its SBOM manifest.

**Command Format**:

```bash
docker compose run --rm linx-xiling -p /app/data/<package_file> -o output/ [optional parameters]

```

**Example**:

```bash
docker compose run --rm linx-xiling -p /app/data/zvbi-0.2.35-8.oe2203sp4.src.rpm -o output/

```

### 3. Repository Scan (`--repo` / `-r`)

Scans a specified software repository URL (such as a YUM/APT repository), recursively analyzes all software packages within the repository, and generates a comprehensive SBOM.

**Command Format**:

```bash
docker compose run --rm linx-xiling -r <repository_URL> -o output/ [optional parameters]

```

**Example**:

```bash
docker compose run --rm linx-xiling -r [https://mirrors.example.com/centos/8-stream/BaseOS/x86_64/os/](https://mirrors.example.com/centos/8-stream/BaseOS/x86_64/os/) -o output/

```

---

## Optional Parameters

In addition to the required mode parameters mentioned above, you can use the following options to adjust the scanning behavior:

| Parameter | Description |
| --- | --- |
| `--help`, `-h` | Show help message and exit |
| `--disable-tqdm` | Disable progress bar display (suitable for logging environments) |
| `--max-workers MAX_WORKERS` | Maximum number of concurrent threads; defaults to the number of CPU cores |
| `--sbom SBOM` | Specify an existing SBOM file (JSON format) for incremental updates to avoid redundant parsing |

---

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
