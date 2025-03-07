# XiLing SBOM Tool 析灵SBOM工具
对ISO镜像或单个软件包进行扫描并生成SBOM（Software Bill of Materials）清单。

## 系统要求
- 操作系统： 凝思安全操作系统V6.0系列 及 Linux发行版

## 硬件要求
- x86_64 CPU
- 4GB以上内存
- 10GB以上可用磁盘空间（需预留足够空间供ISO镜像挂载）

## 运行依赖
- fuseiso
- python (>=3.7)
- glibc (>=2.28)

## 安装
### 安装.rpm包
#### 通过yum安装并自动处理依赖
```
$ sudo yum install RPM_PACKAGE
```
例如：
```
$ sudo yum install ./linx-xiling-1.0-1.x86_64.rpm
```

#### 通过dnf安装并自动处理依赖
```
$ sudo dnf install RPM_PACKAGE
```
例如：
```
$ sudo dnf install ./linx-xiling-1.0-1.x86_64.rpm
```

#### 通过rpm安装
```
$ sudo rpm -ivh RPM_PACKAGE
```
例如：
```
$ sudo rpm -ivh ./linx-xiling-1.0-1.x86_64.rpm
```
请注意，使用rpm进行安装无法自动处理依赖关系，因此需要手动安装依赖。

## 使用说明
### 运行命令
指定一个Linux系统的ISO镜像文件或单个软件包进行扫描，获取其凝思格式SBOM和SPDX格式SBOM：
```
$ linx-xiling [-h] (--iso ISO | --package PACKAGE) --output OUTPUT [--disable-tqdm] [--max-workers MAX_WORKERS] [--sbom SBOM]
```

#### 必需参数
| 参数                            | 说明                  |
|---------------------------------|----------------------|
| --iso ISO, -i ISO               | ISO镜像文件的路径 。   |
| --package PACKAGE, -p PACKAGE   | 软件包的路径。         |
| --output OUTPUT, -o OUTPUT      | SBOM清单输出目录。     |

#### 可选参数
| 参数                               | 说明                  |
|------------------------------------|----------------------|
| --help, -h                         | 显示帮助消息并退出。   |
| --disable-tqdm                     | 禁用进度条显示。       |
| --max-workers MAX_WORKERS          | 最大并发线程数。       |
| --sbom SBOM                        | 指定已存在的SBOM文件（JSON格式）进行增量更新。|

### 源码运行命令
安装必要依赖：
```
$ pip install -r requirements.txt
```

运行工具：
```
$ python3 linx-xiling.py [-h] (--iso ISO | --package PACKAGE) --output OUTPUT [--disable-tqdm] [--max-workers MAX_WORKERS]
```

### 注意事项
#### 如何通过 Docker 运行该工具？
以下命令通过 ```--privileged``` 选项授予容器额外的权限，并通过 ```--cap-add SYS_ADMIN``` 和 ```--device /dev/fuse``` 启用对 FUSE 的访问，从而确保在容器内可以挂载 ISO 镜像：
```
$ docker run -it --privileged --cap-add SYS_ADMIN --device /dev/fuse IMAGE [ARG...]
```

#### 运行日志的保存路径
- 在生产环境中，运行日志保存在```~/.linx-xiling/logs/```目录下。
- 在开发环境中，运行日志保存在项目根目录的```logs/```目录下。
