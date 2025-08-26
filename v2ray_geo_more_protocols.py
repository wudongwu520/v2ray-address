import base64
import re
import json
import socket
import requests
import chardet  # 用于自动检测编码
from urllib.parse import urlparse, quote, unquote
from datetime import datetime
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置项 - 可根据需求调整
MAX_RETRIES = 2  # IP查询重试次数
TIMEOUT = 5  # 网络请求超时时间
MAX_WORKERS = 5  # 并发处理数量
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def decode_v2ray_node(node_str):
    """解码节点字符串，支持更多常用协议"""
    try:
        node_str = node_str.strip()
        
        if node_str.startswith("vmess://"):
            encoded_str = node_str[8:]
            encoded_str = encoded_str.replace('-', '+').replace('_', '/')
            padding = len(encoded_str) % 4
            if padding != 0:
                encoded_str += '=' * (4 - padding)
            
            decoded_bytes = base64.b64decode(encoded_str, validate=True)
            decoded_str = decoded_bytes.decode('utf-8', errors='replace')
            vmess_config = json.loads(decoded_str)
            vmess_config["type"] = "vmess"
            return vmess_config, None

        elif node_str.startswith("ss://"):
            if '#' in node_str:
                node_str, _ = node_str.split('#', 1)
                
            encoded_str = node_str[5:]
            encoded_str = encoded_str.replace('-', '+').replace('_', '/')
            padding = len(encoded_str) % 4
            if padding != 0:
                encoded_str += '=' * (4 - padding)
                
            decoded_bytes = base64.b64decode(encoded_str, validate=True)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            
            if '@' not in decoded_str:
                return None, "ss 节点格式错误（缺少@）"
                
            method_pass, host_port = decoded_str.split('@', 1)
            
            if ':' not in method_pass:
                return None, "ss 节点格式错误（方法与密码分隔符错误）"
                
            method, password = method_pass.split(':', 1)
            
            if ':' not in host_port:
                return None, "ss 节点格式错误（主机与端口分隔符错误）"
                
            host, port = host_port.split(':', 1)
            return {
                "type": "ss",
                "method": method.strip(),
                "password": password.strip(),
                "address": host.strip(),
                "port": port.strip()
            }, None

        # ShadowsocksR 协议
        elif node_str.startswith("ssr://"):
            return {"type": "ssr", "original_url": node_str}, None

        # VLESS 协议
        elif node_str.startswith("vless://"):
            return {"type": "vless", "original_url": node_str}, None

        # Trojan 协议
        elif node_str.startswith("trojan://"):
            return {"type": "trojan", "original_url": node_str}, None

        # TUIC 协议
        elif node_str.startswith("tuic://"):
            return {"type": "tuic", "original_url": node_str}, None

        # Hysteria 系列协议
        elif node_str.startswith("hysteria://"):
            return {"type": "hysteria", "original_url": node_str}, None
        elif node_str.startswith("hysteria2://"):
            return {"type": "hysteria2", "original_url": node_str}, None

        # Socks5 协议 (支持带账号密码的格式)
        elif node_str.startswith("socks5://"):
            return {"type": "socks5", "original_url": node_str}, None

        # HTTP/HTTPS 代理协议
        elif node_str.startswith(("http://", "https://")):
            proto = "http" if node_str.startswith("http://") else "https"
            return {"type": proto, "original_url": node_str}, None

        # WireGuard 协议 (通常是base64编码的配置)
        elif node_str.startswith("wireguard://"):
            return {"type": "wireguard", "original_url": node_str}, None

        # 新增 NaiveProxy 协议
        elif node_str.startswith("naive://"):
            return {"type": "naive", "original_url": node_str}, None

        return None, f"不支持的协议: {node_str[:10]}..."

    except base64.binascii.Error as e:
        return None, f"Base64解码错误: {str(e)}"
    except json.JSONDecodeError as e:
        return None, f"JSON解析错误: {str(e)}"
    except Exception as e:
        return None, f"解码错误: {str(e)}"


def get_ip_address(host):
    """解析域名到IP，增加缓存和详细错误信息"""
    if not host:
        return None
        
    if not hasattr(get_ip_address, "cache"):
        get_ip_address.cache = {}
        
    if host in get_ip_address.cache:
        return get_ip_address.cache[host]
        
    try:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
            get_ip_address.cache[host] = host
            return host
            
        ip = socket.gethostbyname(host)
        get_ip_address.cache[host] = ip
        return ip
    except socket.gaierror as e:
        print(f"⚠️ 域名解析失败 ({host}): {str(e)}")
        return None
    except Exception as e:
        print(f"⚠️ IP解析异常 ({host}): {str(e)}")
        return None


def get_geo_info(ip):
    """获取IP地理位置，增加重试和多API备份"""
    if not ip:
        return "未知"
        
    if not hasattr(get_geo_info, "cache"):
        get_geo_info.cache = {}
        
    if ip in get_geo_info.cache:
        return get_geo_info.cache[ip]
    
    apis = [
        f"http://ip-api.com/json/{ip}?lang=zh-CN",
        f"https://ipinfo.io/{ip}/json",
        f"https://api.ip.sb/geoip/{ip}?lang=zh-CN"
    ]
    
    headers = {"User-Agent": USER_AGENT}
    
    for api in apis:
        for retry in range(MAX_RETRIES + 1):
            try:
                response = requests.get(api, timeout=TIMEOUT, headers=headers)
                response.raise_for_status()
                data = response.json()
                
                if "country" in data:
                    country = data["country"]
                    if len(country) == 2 and api == apis[0]:
                        country = data.get("country", "未知")
                    get_geo_info.cache[ip] = country
                    return country
                    
            except Exception as e:
                if retry < MAX_RETRIES:
                    time.sleep(0.5)
                    continue
                print(f"⚠️ IP查询失败 ({ip} via {api}): {str(e)}")
                break
    
    get_geo_info.cache[ip] = "未知"
    return "未知"


def encode_v2ray_node(config, country):
    """重新编码节点，支持新增协议"""
    try:
        protocol = config.get("type")
        if not protocol:
            return None

        if protocol == "vmess":
            original_ps = config.get("ps", "")
            config["ps"] = f"[{country}] {original_ps}".strip()
            json_str = json.dumps(config, ensure_ascii=False, separators=(',', ':'))
            encoded = base64.urlsafe_b64encode(json_str.encode()).decode()
            return f"vmess://{encoded}"

        elif protocol == "ss":
            core = f"{config['method']}:{config['password']}@{config['address']}:{config['port']}"
            encoded_core = base64.urlsafe_b64encode(core.encode()).decode()
            return f"ss://{encoded_core}#{quote(f'[{country}]')}"

        # 通用协议处理逻辑（保留原始URL，添加国家备注）
        elif protocol in [
            "ssr", "vless", "trojan", "tuic", 
            "hysteria", "hysteria2", "socks5", 
            "http", "https", "wireguard", "naive"
        ]:
            url = config["original_url"]
            # 移除旧备注，添加新的国家备注
            if "#" in url:
                url = url.split("#")[0]
            return f"{url}#{quote(f'[{country}]')}"

        return None
    except Exception as e:
        print(f"⚠️ 节点编码失败: {str(e)}")
        return None


def process_single_node(args):
    """处理单个节点（用于并发）"""
    i, node = args
    try:
        config, err = decode_v2ray_node(node)
        if not config:
            return (False, f"❌ 节点 {i} 解码失败: {err}", None)

        host = config.get("address")
        if not host and "original_url" in config:
            # 从URL中提取主机名（适用于各种协议）
            parsed = urlparse(config["original_url"])
            host = parsed.hostname

        ip = get_ip_address(host)
        country = get_geo_info(ip) if ip else "未知"

        new_node = encode_v2ray_node(config, country)
        if new_node:
            return (True, f"✅ 节点 {i} 成功: [{country}] {ip or host}", new_node)
        else:
            return (False, f"⚠️ 节点 {i} 重新编码失败", None)
    except Exception as e:
        return (False, f"❌ 节点 {i} 处理异常: {str(e)}", None)


def detect_file_encoding(file_path):
    """使用chardet检测文件编码"""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(4096)
        
        result = chardet.detect(raw_data)
        encoding = result['encoding']
        if encoding:
            encoding = encoding.lower()
            if encoding == 'utf-8' and raw_data.startswith(b'\xef\xbb\xbf'):
                return 'utf-8-sig'
            encoding_map = {
                'windows-1252': 'latin-1',
                'iso-8859-1': 'latin-1',
                'gb2312': 'gbk',
            }
            return encoding_map.get(encoding, encoding)
        return 'utf-8'
    except Exception as e:
        print(f"编码检测失败，使用默认编码utf-8: {str(e)}")
        return 'utf-8'


def process_nodes(input_file, output_file):
    """批量处理节点，支持更多协议"""
    start_time = datetime.now()
    
    if not os.path.exists(input_file):
        print(f"错误: 输入文件不存在 - {input_file}")
        return
        
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    encoding = detect_file_encoding(input_file)
    print(f"检测到文件编码: {encoding} (将使用此编码读取文件)")

    try:
        with open(input_file, "r", encoding=encoding, errors='replace') as f:
            nodes = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"使用 {encoding} 编码读取失败，尝试utf-8: {str(e)}")
        try:
            with open(input_file, "r", encoding='utf-8', errors='replace') as f:
                nodes = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"读取文件失败: {str(e)}")
            return

    if not nodes:
        print("警告: 输入文件中未找到有效节点")
        return

    print(f"开始处理 {len(nodes)} 个节点...")
    results = []
    success_count = 0
    fail_count = 0
    country_stats = {}
    protocol_stats = {}  # 新增协议统计

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_single_node, (i+1, node)) for i, node in enumerate(nodes)]
        
        for future in as_completed(futures):
            success, msg, new_node = future.result()
            print(msg)
            
            if success and new_node:
                results.append(new_node)
                success_count += 1
                # 提取国家统计
                country_match = re.search(r'\[(.*?)\]', msg)
                if country_match:
                    country = country_match.group(1)
                    country_stats[country] = country_stats.get(country, 0) + 1
                # 提取协议类型统计
                for proto in ["vmess", "ss", "ssr", "vless", "trojan", "tuic", "hysteria", "hysteria2", "socks5", "http", "https", "wireguard", "naive"]:
                    if new_node.startswith(f"{proto}://"):
                        protocol_stats[proto] = protocol_stats.get(proto, 0) + 1
                        break
            else:
                fail_count += 1

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(results))
    except Exception as e:
        print(f"保存文件失败: {str(e)}")
        return

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "="*50)
    print(f"处理完成! 耗时: {duration:.2f}秒")
    print(f"总节点数: {len(nodes)}")
    print(f"成功: {success_count} 个")
    print(f"失败: {fail_count} 个")
    print("\n协议分布:")
    for proto, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
        print(f"  {proto}: {count} 个")
    print("\n国家/地区分布:")
    for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True):
        print(f"  {country}: {count} 个")
    print(f"\n输出文件: {os.path.abspath(output_file)}")
    print("="*50)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("用法: python v2ray_geo_more_protocols.py 输入文件 输出文件")
        print("示例: python v2ray_geo_more_protocols.py nodes.txt nodes_new.txt")
        sys.exit(1)

    try:
        import chardet
    except ImportError:
        print("检测到未安装chardet库，正在尝试自动安装...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "chardet"])
    
    process_nodes(sys.argv[1], sys.argv[2])
    