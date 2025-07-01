# Xray-Dashboard

一个基于 Web 的 Xray-core 监控与管理面板。

<img width="1505" alt="image" src="https://github.com/user-attachments/assets/fbf5524d-5d6b-4ba2-8f2c-fd9bbaa2c43b" />

<img width="1365" alt="image" src="https://github.com/user-attachments/assets/b8b7b4a0-e756-4d13-aede-058f57a47447" />

<img width="1506" alt="image" src="https://github.com/user-attachments/assets/6161bed3-7d37-4b37-9c51-cdf984fd4701" />


---

## 功能列表

* **实时监控**
    * 服务器系统资源 (CPU, 内存, 磁盘)
    * Xray 核心流量统计 (上传/下载)
    * 实时连接日志分析，并按来源 IP 智能分组
    * IP 地理位置查询 (使用本地 GeoLite2 数据库)
    * 连接数来源饼图可视化

* **安全与控制**
    * **威胁情报**: 自动调用 VirusTotal API 对连接目标进行信誉评级 (恶意/可疑/无害)。
    * **手动封禁**: 通过 `iptables` 一键封禁或解封任意可疑 IP。
    * **IP 限速**: 通过 `tc` 对任意 IP 单独精细化设置下载速率上限。
    * **自动防御**: 内置后台任务，可根据预设规则（如：短时间内多次访问恶意站点）自动封禁来源 IP。
    * **安全登录**: 使用哈希密码和 Flask-Session 的强制登录认证。

##  快速开始

本项目提供了一个一键部署脚本，可以在一台全新的 Debian 或 Ubuntu 服务器上快速完成所有环境配置。

#### 1. 准备工作

* 一台全新的 Debian 或 Ubuntu 服务器。
* 一个具有 `sudo` 权限的普通用户。

#### 2. 执行一键部署脚本

将项目根目录下的 `setup.sh` 脚本上传到你的服务器，然后执行它。

```bash
# 给予脚本执行权限
chmod +x setup.sh

# 推荐使用 sudo 执行，它会自动识别你的用户名来设置权限
sudo ./setup.sh
```

脚本会自动安装并配置好 Python, Redis, Xray, `iptables`, `tc` 等所有依赖。

#### 3. 上传项目文件

脚本执行完毕后，将本项目中的以下文件/目录上传到脚本创建的项目文件夹中（通常是 `/home/你的用户名/xray-dashboard/`）：

* `app.py`
* `templates/` (整个目录)

#### 4. 配置

* **配置 Xray**:
    1.  将项目中的 `xray_config.json` 的内容，完整地复制到服务器的 `/usr/local/etc/xray/config.json` 文件中。
    2.  重启 Xray 服务: `sudo systemctl restart xray`

* **配置 Dashboard**:
    1.  **生成你自己的密码哈希**:
        在服务器的项目目录中，先激活虚拟环境 (`source venv/bin/activate`)，然后执行以下命令来生成你的密码哈希值。记得替换 `'你的安全密码'`。
        ```bash
        python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('你的安全密码'))"
        ```
    2.  **更新 `app.py`**:
        编辑 `app.py` 文件，将 `PASSWORD_HASH` 和 `VT_API_KEY` 变量的值替换为你自己的。同时，确认 `NETWORK_INTERFACE` 变量的值是你服务器的正确网络接口名 (如 `ens4`)。

#### 5. 启动应用

一切就绪！现在可以启动 Dashboard 服务了。

```bash
# 进入项目目录
cd ~/xray-dashboard

# 激活虚拟环境
source venv/bin/activate

# 启动 Flask 应用
python3 app.py
```

现在，通过浏览器访问 `http://你的服务器IP:8080` 即可看到登录页面。（因为安全巡检需要进行sudo权限的tc规则配置，启动时可能需要输入用户密码）

##  技术栈

* **后端**: Python, Flask, APScheduler
* **前端**: HTML, CSS, JavaScript, Bootstrap 5, Chart.js
* **数据**: Redis (用于缓存和状态管理), SQLite (可选)
* **系统工具**: `iptables`, `tc`
* **核心**: Xray-core, gRPC

##  注意

* 本项目直接与系统底层命令交互，请务必使用一个**极其复杂**的登录密码。
* `python3 app.py` 启动的是开发服务器。在生产环境中，建议使用 `Gunicorn` + `Nginx` 进行部署。
