# 使用debian:bookworm-slim作为基础镜像
FROM debian:bookworm-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# 可在默认源连接缓慢时通过 --build-arg 选择其他 Debian 镜像站。
ARG DEBIAN_MIRROR=http://deb.debian.org/debian
ARG DEBIAN_SECURITY_MIRROR=http://deb.debian.org/debian-security

# 安装系统依赖和Python
RUN sed -i \
        -e "s|^URIs: http://deb.debian.org/debian$|URIs: ${DEBIAN_MIRROR}|" \
        -e "s|^URIs: http://deb.debian.org/debian-security$|URIs: ${DEBIAN_SECURITY_MIRROR}|" \
        /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    python3-rpm \
    squashfs-tools \
    openssl \
    rpm \
    zstd \
    pkg-config \
    libicu-dev \
    libarchive-dev \
    gcc \
    g++ \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 创建并激活虚拟环境
RUN python3 -m venv --system-site-packages /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 复制项目文件
COPY . .

# 授予执行权限；源码仓库可以不包含可选的 OSV Scanner 二进制文件。
# 未提供时，源码依赖识别沿用运行时的告警和空结果回退逻辑。
RUN chmod +x linx-xiling.py && \
    if [ -f actions/scanner/osv-scanner/osv-scanner_linux_amd64 ]; then \
        chmod +x actions/scanner/osv-scanner/osv-scanner_linux_amd64; \
    else \
        printf '%s\n' 'OSV Scanner 未随源码提供，源码依赖识别将不可用。'; \
    fi

# 在虚拟环境中安装Python依赖
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 设置入口点
ENTRYPOINT ["python", "linx-xiling.py"]
