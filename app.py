import grpc
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import re
from collections import defaultdict, Counter
import os
from functools import wraps
import geoip2.database
import psutil
import subprocess
import requests 
import time
import threading
from queue import Queue
import redis
import json
from apscheduler.schedulers.background import BackgroundScheduler

# 导入密码哈希工具
from werkzeug.security import check_password_hash
# 导入所有正确路径的 gRPC 文件
from app.stats.command import command_pb2 as stats_command_pb2, command_pb2_grpc as stats_command_pb2_grpc
from app.proxyman.command import command_pb2 as proxyman_command_pb2, command_pb2_grpc as proxyman_command_pb2_grpc
from google.protobuf import any_pb2
from common.protocol.user_pb2 import User

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()

# --- 安全与配置 ---
PASSWORD_HASH = 'scrypt:32768:8:1$kuRme4WyAGpJBGJa$c02221f2bebd0ac754930acb4f29151503c7d857f1a94185607e00e1a235790594d3d65217e594c25c3f96abdd29d9a5bcff3e72558ec501011fa2058bcd1499'
XRAY_API_ADDRESS = '127.0.0.1:10085'
XRAY_ACCESS_LOG = '/var/log/xray/access.log'
NETWORK_INTERFACE = "ens4" 
VT_API_KEY = ''

# --- Redis 配置 ---
redis_pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
redis_conn = redis.Redis(connection_pool=redis_pool)

# --- 应用内状态与缓存 ---
ip_limit_state = {}
next_tc_class_id = 100
reputation_query_queue = Queue()
VT_API_QUOTA_EXCEEDED = False
VT_QUOTA_RESET_TIME = 0
# --- 关键修正：重新定义缓存过期时间变量 ---
CACHE_EXPIRATION = 3600 * 24 # 缓存过期时间（秒），这里是24小时

# --- 自动化封禁规则配置 ---
AUTO_BAN_THRESHOLD = 10 # 在指定时间内访问恶意域名超过10次则封禁
AUTO_BAN_TIMEFRAME = 60 # 时间窗口（秒），这里是1分钟
AUTO_BAN_DURATION = 3600 # 自动封禁时长（秒），这里是1小时

# --- 初始化 GeoIP 读取器 ---
try: geoip_reader = geoip2.database.Reader('./GeoLite2-City.mmdb')
except FileNotFoundError: geoip_reader = None; print("Warning: GeoLite2-City.mmdb not found.")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def run_command(command):
    try:
        full_command = command.replace('sudo iptables', 'sudo /usr/sbin/iptables').replace('sudo systemctl', 'sudo /bin/systemctl').replace('sudo tc', 'sudo /usr/sbin/tc')
        result = subprocess.run(full_command, shell=True, check=True, capture_output=True, text=True)
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e: return False, e.stderr.strip()

# --- 威胁情报查询 (后台工作线程) ---
def reputation_worker():
    global VT_API_QUOTA_EXCEEDED, VT_QUOTA_RESET_TIME
    while True:
        if VT_API_QUOTA_EXCEEDED and time.time() < VT_QUOTA_RESET_TIME:
            time.sleep(60)
            continue
        elif VT_API_QUOTA_EXCEEDED and time.time() >= VT_QUOTA_RESET_TIME:
            VT_API_QUOTA_EXCEEDED = False
            print("--- [INFO] API 熔断已解除，恢复查询。")
        
        target = reputation_query_queue.get()
        get_target_reputation(target)
        reputation_query_queue.task_done()

def get_target_reputation(target):
    global VT_API_QUOTA_EXCEEDED, VT_QUOTA_RESET_TIME
    cached_result = redis_conn.get(f"reputation:{target}")
    if cached_result: return json.loads(cached_result)

    headers = {'x-apikey': VT_API_KEY}
    url = f'https://www.virustotal.com/api/v3/domains/{target}' if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target) else f'https://www.virustotal.com/api/v3/ip_addresses/{target}'
    
    try:
        time.sleep(16)
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious, suspicious = stats.get('malicious', 0), stats.get('suspicious', 0)
        
        if malicious > 0: reputation = {'status': '恶意', 'class': 'danger'}
        elif suspicious > 0: reputation = {'status': '可疑', 'class': 'warning'}
        else: reputation = {'status': '无害', 'class': 'success'}
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            VT_API_QUOTA_EXCEEDED = True
            VT_QUOTA_RESET_TIME = time.time() + 3600
            reputation = {'status': 'API超限', 'class': 'dark'}
        else: reputation = {'status': '未知', 'class': 'secondary'}
    except Exception as e:
        print(f"Error getting reputation for {target}: {e}")
        reputation = {'status': '查询异常', 'class': 'dark'}

    redis_conn.setex(f"reputation:{target}", CACHE_EXPIRATION, json.dumps(reputation))
    return reputation

# --- 自动化防御核心逻辑 ---
def auto_ban_check():
    """后台定时任务：检查并自动封禁可疑IP"""
    print(f"--- [Auto-Ban] 开始执行安全巡检...")
    now = time.time()
    try:
        with open(XRAY_ACCESS_LOG, 'r') as f:
            lines = f.readlines()
        
        recent_logs = []
        log_pattern = re.compile(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\.\d+ from ([\d\.:a-fA-F\[\]]+) accepted tcp:([\w\.-]+):(\d+)')
        for line in reversed(lines):
            match = log_pattern.search(line)
            if match:
                log_time_str = match.group(1)
                log_timestamp = time.mktime(time.strptime(log_time_str, "%Y/%m/%d %H:%M:%S"))
                if (now - log_timestamp) > AUTO_BAN_TIMEFRAME:
                    break
                ip_full = match.group(2)
                ip_clean = ip_full.rsplit(':', 1)[0]
                if ip_clean.startswith('[') and ip_clean.endswith(']'):
                    ip_clean = ip_clean[1:-1]
                recent_logs.append({'ip': ip_clean, 'host': match.group(3)})

        malicious_access_counts = Counter()
        for log in recent_logs:
            reputation_raw = redis_conn.get(f"reputation:{log['host']}")
            if reputation_raw:
                reputation = json.loads(reputation_raw)
                if reputation.get('status') == '恶意':
                    malicious_access_counts[log['ip']] += 1
        
        banned_ips_raw = redis_conn.hgetall("banned_ips")
        manually_banned_ips = [ip.decode() for ip in banned_ips_raw.keys()]
        
        for ip, count in malicious_access_counts.items():
            auto_ban_key = f"auto_banned:{ip}"
            # 检查是否已被手动或自动封禁
            if ip not in manually_banned_ips and not redis_conn.exists(auto_ban_key):
                if count >= AUTO_BAN_THRESHOLD:
                    print(f"--- [Auto-Ban] 检测到高风险行为！IP: {ip}, 访问恶意域名次数: {count}。正在执行自动封禁...")
                    is_success, _ = run_command(f"sudo iptables -I INPUT -s {ip} -j DROP")
                    if is_success:
                        redis_conn.setex(auto_ban_key, AUTO_BAN_DURATION, "Malicious Domain Access")
                        print(f"--- [Auto-Ban] IP: {ip} 已被自动封禁，时长: {AUTO_BAN_DURATION}秒。")

    except Exception as e:
        print(f"--- [Auto-Ban] 安全巡检任务出错: {e}")

# --- 数据获取函数 ---
def get_auto_banned_ips():
    """获取所有被自动封禁的IP及其剩余时间"""
    auto_banned_list = []
    keys = redis_conn.keys("auto_banned:*")
    for key in keys:
        ip = key.decode().split(':')[1]
        ttl = redis_conn.ttl(key)
        auto_banned_list.append({'ip': ip, 'ttl': ttl})
    return auto_banned_list

def get_connection_data(num_lines=1000):
    try:
        with open(XRAY_ACCESS_LOG, 'r') as f: lines = f.readlines()[-num_lines:]
        grouped_connections = defaultdict(list)
        log_pattern = re.compile(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+) from ([\d\.:a-fA-F\[\]]+) accepted tcp:([\w\.-]+):(\d+)')
        
        unique_hosts_to_query = set()
        for line in lines:
            match = log_pattern.search(line)
            if match:
                _, _, destination_host, _ = match.groups()
                if not redis_conn.exists(f"reputation:{destination_host}"):
                    unique_hosts_to_query.add(destination_host)
        
        if not VT_API_QUOTA_EXCEEDED:
            for host in unique_hosts_to_query:
                if host not in list(reputation_query_queue.queue):
                    reputation_query_queue.put(host)

        for line in lines:
            match = log_pattern.search(line)
            if match:
                timestamp, source_ip_with_port, destination_host, destination_port = match.groups()
                if source_ip_with_port.startswith('127.0.0.1'): continue
                
                ip_address = source_ip_with_port.rsplit(':', 1)[0]
                if ip_address.startswith('[') and ip_address.endswith(']'): ip_address = ip_address[1:-1]
                
                location = "未知"
                if geoip_reader:
                    try:
                        loc_data = geoip_reader.city(ip_address)
                        country = loc_data.country.names.get('zh-CN', loc_data.country.name)
                        city = loc_data.city.names.get('zh-CN', loc_data.city.name) if loc_data.city else None
                        if country and city: location = f"{country}, {city}"
                        elif country: location = country
                    except geoip2.errors.AddressNotFoundError: location = "私有/保留地址"
                
                cached_reputation = redis_conn.get(f"reputation:{destination_host}")
                reputation = json.loads(cached_reputation) if cached_reputation else {'status': '查询中...', 'class': 'light'}
                if VT_API_QUOTA_EXCEEDED: reputation = {'status': 'API超限', 'class': 'dark'}
                
                grouped_connections[ip_address].append({
                    'timestamp': timestamp, 'destination': f"{destination_host}:{destination_port}",
                    'location': location, 'reputation': reputation
                })
        return grouped_connections
    except Exception as e: print(f"Error reading access log: {e}"); return {}

def get_banned_ips():
    is_success, output = run_command("sudo iptables -L INPUT -n --line-numbers")
    if not is_success: print(f"Failed to list iptables rules: {output}"); return []
    banned_list = []; lines = output.split('\n')
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 6 and parts[1] == 'DROP': banned_list.append({'num': parts[0], 'ip': parts[3]})
    return banned_list

def get_limited_ips():
    return [{'ip': ip, 'rate': data['rate'], 'mark': data['mark']} for ip, data in ip_limit_state.items()]

def get_stats_data():
    stats_data = []; patterns = {"uplink": "inbound>>>proxy-inbound>>>traffic>>>uplink", "downlink": "inbound>>>proxy-inbound>>>traffic>>>downlink"}
    for key, pattern in patterns.items():
        try:
            with grpc.insecure_channel(XRAY_API_ADDRESS) as channel:
                stub = stats_command_pb2_grpc.StatsServiceStub(channel)
                response = stub.QueryStats(stats_command_pb2.QueryStatsRequest(pattern=pattern, reset=False))
                if response.stat: stats_data.append({'name': response.stat[0].name, 'value': round(response.stat[0].value / 1024 / 1024, 2)})
        except Exception as e: print(f"Error querying {key} stats: {e}")
    return stats_data

# --- 页面路由 ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password and check_password_hash(PASSWORD_HASH, password): session['logged_in'] = True; return redirect(url_for('index'))
        else: flash('密码错误，请重试！', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None); flash('您已成功登出。', 'success'); return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

# --- API 与控制路由 ---
@app.route('/api/data')
@login_required
def api_data():
    sys_info = {'cpu': psutil.cpu_percent(interval=1), 'memory': psutil.virtual_memory().percent, 'disk': psutil.disk_usage('/').percent}
    stats = get_stats_data()
    connections = get_connection_data()
    banned_ips = get_banned_ips()
    limited_ips = get_limited_ips()
    auto_banned_ips = get_auto_banned_ips()
    
    return jsonify({
        'sys_info': sys_info, 'stats': stats, 'connections': connections,
        'banned_ips': banned_ips, 'limited_ips': limited_ips,
        'auto_banned_ips': auto_banned_ips
    })

# --- 主动控制路由 ---
@app.route('/actions/ban/<ip>', methods=['POST'])
@login_required
def ban_ip(ip):
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip): return jsonify({'status': 'error', 'message': '无效的 IP 地址格式'}), 400
    is_success, output = run_command(f"sudo iptables -I INPUT -s {ip} -j DROP")
    if is_success:
        redis_conn.hset("banned_ips", ip, "manual")
        return jsonify({'status': 'success', 'message': f'IP {ip} 已被手动封禁。'})
    else: return jsonify({'status': 'error', 'message': f'封禁失败: {output}'}), 500

@app.route('/actions/unban/<int:rule_num>/<ip>', methods=['POST'])
@login_required
def unban_ip(rule_num, ip):
    is_success, output = run_command(f"sudo iptables -D INPUT {rule_num}")
    if is_success:
        redis_conn.hdel("banned_ips", ip)
        return jsonify({'status': 'success', 'message': f'规则 #{rule_num} ({ip}) 已被移除。'})
    else: return jsonify({'status': 'error', 'message': f'解封失败: {output}'}), 500

# ... 省略其他控制路由 ...

def initialize_app_state():
    # ... 省略初始化代码 ...
    print("应用启动，正在初始化...")
    # 清空 Redis 中的手动封禁列表，以与 iptables 同步
    redis_conn.delete("banned_ips")
    
    # 启动时，将 iptables 中已有的规则加载到 Redis
    existing_banned = get_banned_ips()
    if existing_banned:
        pipe = redis_conn.pipeline()
        for item in existing_banned:
            pipe.hset("banned_ips", item['ip'], "manual")
        pipe.execute()
        print(f"从 iptables 加载了 {len(existing_banned)} 条已存在的手动封禁规则到 Redis。")

if __name__ == '__main__':
    # 启动后台工作线程
    threading.Thread(target=reputation_worker, daemon=True).start()
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(auto_ban_check, 'interval', minutes=1)
    scheduler.start()
    print("后台安全巡检任务已启动，每分钟执行一次。")
    
    initialize_app_state()
    app.run(host='0.0.0.0', port=8080)

