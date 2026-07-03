# 使用debian:bookworm-slim作为基础镜像
FROM debian:bookworm-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# 安装系统依赖和Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    rpm \
    pkg-config \
    libicu-dev \
    libarchive-dev \
    gcc \
    g++ \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 创建并激活虚拟环境
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 复制项目文件
COPY . .

# 授予执行权限
RUN chmod +x linx-xiling.py && \
    chmod +x actions/scanner/osv-scanner/osv-scanner_linux_amd64

# 在虚拟环境中安装Python依赖
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 设置入口点
ENTRYPOINT ["python", "linx-xiling.py"]
