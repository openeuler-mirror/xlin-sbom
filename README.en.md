# XiLing SBOM Tool
The XiLing SBOM Tool scans ISO images or individual software packages to generate an SBOM (Software Bill of Materials) list.

## System Requirements
- OS: Linx OS V6.0 series or Linux distributions

## Hardware Requirements
- x86_64 CPU
- At least 4GB of RAM
- At least 10GB of available disk space (sufficient space required for ISO image mounting)

## Runtime Dependencies
- fuseiso
- Python (>=3.7)
- glibc (>=2.28)

## Installation
### Install the .rpm package
#### Install via yum with automatic dependency handling
```
$ sudo yum install RPM_PACKAGE
```
For example:
```
$ sudo yum install ./linx-xiling-1.0-1.x86_64.rpm
```

#### Install via dnf with automatic dependency handling
```
$ sudo dnf install RPM_PACKAGE
```
For example:
```
$ sudo dnf install ./linx-xiling-1.0-1.x86_64.rpm
```

#### Install via rpm
```
$ sudo rpm -ivh RPM_PACKAGE
```
For example:
```
$ sudo rpm -ivh ./linx-xiling-1.0-1.x86_64.rpm
```
Note: Using rpm does not handle dependencies automatically, so you need to install them manually.

## Usage Instructions
### Running the Command
Scan a Linux ISO image file or a single software package to generate both a Condensed Thinking-format SBOM and an SPDX-format SBOM:
```
$ linx-xiling [-h] (--iso ISO | --package PACKAGE) --output OUTPUT [--disable-tqdm] [--max-workers MAX_WORKERS] [--sbom SBOM]
```

#### Required Parameters
| Parameter                     | Description                          |
| ----------------------------- | ------------------------------------ |
| --iso ISO, -i ISO             | Path to the ISO image file.          |
| --package PACKAGE, -p PACKAGE | Path to the software package.        |
| --output OUTPUT, -o OUTPUT    | Output directory for the SBOM files. |

#### Optional Parameters
| Parameter                 | Description                           |
| ------------------------- | ------------------------------------- |
| --help, -h                | Show help message and exit.           |
| --disable-tqdm            | Disable progress bar display.         |
| --max-workers MAX_WORKERS | Maximum number of concurrent threads. |
| --sbom SBOM               | Specify an existing SBOM file (JSON format) for incremental updates.|

### Running from Source
Install required dependencies:
```
$ pip install -r requirements.txt
```

Run the tool:
```
$ python3 linx-xiling.py [-h] (--iso ISO | --package PACKAGE) --output OUTPUT [--disable-tqdm] [--max-workers MAX_WORKERS]
```

### Notes
#### How to Run the Tool via Docker?
The following command uses the ```--privileged``` option to grant additional privileges to the container and enables access to FUSE via the ```--cap-add SYS_ADMIN``` and ```--device /dev/fuse``` options, ensuring ISO images can be mounted inside the container:
```
$ docker run -it --privileged --cap-add SYS_ADMIN --device /dev/fuse IMAGE [ARG...]
```

#### Log File Paths
- In production environments, logs are saved in the ```~/.linx-xiling/logs/``` directory.
- In development environments, logs are saved in the ```logs/``` directory under the project root.
