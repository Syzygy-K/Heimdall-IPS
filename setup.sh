#!/bin/bash
#
# Project Heimdall / X-SOC - 一键环境配置脚本
# (Xray Security Operations & Control Dashboard - One-Click Setup Script)
#
# 功能:
# 1. 安装所有系统及 Python 依赖 (包括 Redis)
# 2. 启动并设置 Redis 开机自启
# 3. 安装最新版 Xray-core
# 4. 创建项目目录并下载所需资源 (GeoIP 数据库, Xray 源码)
# 5. 自动创建并配置安全的 sudoers 权限
# 6. 自动初始化 TC 网络流量控制规则
# 7. 自动编译所有 gRPC API 文件并设置 Python 包环境
#
# 使用方法:
# 1. 将此脚本上传到你的新服务器，例如 /tmp/setup.sh
# 2. 给予执行权限: chmod +x /tmp/setup.sh
# 3. 使用 sudo 执行脚本: sudo /tmp/setup.sh

# --- 配置项 ---
# 自动获取执行 sudo 命令的用户名，用于 sudoers 配置
# 如果你是用 root 用户直接执行的，请手动修改为你日常使用的用户名
CURRENT_USER=${SUDO_USER:-$USER}

# 项目将被安装在用户的主目录下
PROJECT_DIR="/home/$CURRENT_USER/xray-dashboard"

# --- 脚本开始 ---
set -e # 任何命令失败则立即退出

echo "================================================="
echo " Heimdall / X-SOC 一键环境配置脚本启动... "
echo "================================================="
echo ""

echo "--- [1/7] 正在更新系统并安装核心依赖... ---"
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv git iptables wget unzip redis-server

echo "--- [2/7] 正在配置并启动 Redis... ---"
sudo systemctl enable redis-server
sudo systemctl start redis-server
echo "Redis 已启动并设置为开机自启。"

echo "--- [3/7] 正在安装最新版 Xray-core... ---"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

echo "--- [4/7] 正在创建项目目录并下载资源... ---"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

echo "正在下载 GeoIP 数据库..."
wget https://git.io/GeoLite2-City.mmdb -O GeoLite2-City.mmdb

echo "正在克隆 Xray-core 源码 (用于编译API)..."
# 如果目录已存在，先删除，确保获取最新代码
rm -rf Xray-core
git clone https://github.com/XTLS/Xray-core.git

echo "--- [5/7] 正在配置 Python 虚拟环境并安装库... ---"
python3 -m venv venv
# 直接使用虚拟环境中的 pip 来安装，避免激活/退出的复杂性
./venv/bin/pip install flask grpcio grpcio-tools geoip2 psutil werkzeug redis APScheduler requests

echo "--- [6/7] 正在编译 gRPC API 文件... ---"
# 清理可能存在的旧文件
rm -rf app common core config_pb2* v2ray google

# 定义一个函数来简化编译命令
compile_proto() {
    ./venv/bin/python3 -m grpc_tools.protoc --proto_path=./Xray-core --python_out=. --grpc_python_out=. "$1"
}

# 编译所有必需的 .proto 文件
compile_proto ./Xray-core/app/stats/command/command.proto
compile_proto ./Xray-core/app/proxyman/command/command.proto
compile_proto ./Xray-core/common/protocol/user.proto
compile_proto ./Xray-core/common/serial/typed_message.proto
compile_proto ./Xray-core/core/config.proto

# 创建 __init__.py 文件，将目录转为 Python 包
touch app/__init__.py app/stats/__init__.py app/stats/command/__init__.py
touch app/proxyman/__init__.py app/proxyman/command/__init__.py
touch common/__init__.py common/protocol/__init__.py common/serial/__init__.py
touch core/__init__.py
echo "gRPC API 文件编译完成。"

echo "--- [7/7] 正在配置系统权限与网络规则... ---"

# 配置 Sudoers
echo "正在为用户 '$CURRENT_USER' 配置 sudoers 权限..."
SUDOERS_FILE="/etc/sudoers.d/xray_dashboard"
# 使用 cat 和 EOF 来创建多行文件，更清晰可靠
sudo bash -c "cat > $SUDOERS_FILE" << EOF
# 授权 $CURRENT_USER 用户免密执行 Xray Dashboard 所需的特定命令
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart xray.service
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L INPUT -n --line-numbers
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -I INPUT -s * -j DROP
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -D INPUT *
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -t mangle -L POSTROUTING -n --line-numbers
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -t mangle -L POSTROUTING -n -v
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -t mangle -A POSTROUTING -d * -j MARK --set-mark *
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -t mangle -D POSTROUTING *
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/tc *
EOF

# 验证 sudoers 文件语法
sudo visudo -c -f "$SUDOERS_FILE"
echo "Sudoers 文件已在 $SUDOERS_FILE 创建并验证成功。"

# 初始化 TC (流量控制)
echo "现在需要初始化流量控制规则 (TC)..."
# 自动检测主网络接口
INTERFACE_NAME=$(ip -o -4 route show to default | awk '{print $5}')
if [ -z "$INTERFACE_NAME" ]; then
    echo "无法自动检测到主网络接口。请输入你的网络接口名 (例如: eth0, ens4):"
    read -r INTERFACE_NAME
fi
echo "将使用网络接口: $INTERFACE_NAME"

echo "正在清理并初始化 TC 规则..."
sudo /usr/sbin/tc qdisc del dev "$INTERFACE_NAME" root 2>/dev/null || true
sudo /usr/sbin/tc qdisc add dev "$INTERFACE_NAME" root handle 1: htb default 10
sudo /usr/sbin/tc class add dev "$INTERFACE_NAME" parent 1: classid 1:1 htb rate 1000mbit
sudo /usr/sbin/tc class add dev "$INTERFACE_NAME" parent 1:1 classid 1:10 htb rate 1000mbit
sudo /usr/sbin/tc filter add dev "$INTERFACE_NAME" protocol ip parent 1:0 prio 1 handle 10 fw classid 1:10

echo ""
echo "=============================================="
echo " 环境配置成功"
echo "=============================================="
echo ""
echo "下一步操作:"
echo "1. 将你的项目文件 (app.py, templates目录, static目录) 上传到项目文件夹: $PROJECT_DIR"
echo "2. 将 xray_config.json 的内容复制到 /usr/local/etc/xray/config.json"
echo "3. 根据你的需求，编辑 app.py 里的密码哈希和网络接口名 (当前设置为 $INTERFACE_NAME)。"
echo "4. 重启 Xray 服务: sudo systemctl restart xray"
echo "5. 进入项目目录，激活虚拟环境并启动应用:"
echo "   cd $PROJECT_DIR"
echo "   source venv/bin/activate"
echo "   python3 app.py"
echo ""
echo "现在，可以通过浏览器访问 http://<你的服务器IP>:8080"
echo ""

