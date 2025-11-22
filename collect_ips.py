import requests
from bs4 import BeautifulSoup
import re
import logging
from collections import defaultdict
import ipaddress
from time import sleep

# 设置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 目标URL列表
urls = [
    'https://ip.164746.xyz',
    'https://addressesapi.090227.xyz/CloudFlareYes',
    'https://addressesapi.090227.xyz/ip.164746.xyz',
    'https://ipdb.030101.xyz/bestcfv4'
]

# 预编译 IP 正则表达式
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# 增加网络 session + 自动重试
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(max_retries=3)
session.mount("http://", adapter)
session.mount("https://", adapter)

# 验证是否为合法 IP
def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# 获取IP所属国家
def get_ip_country(ip):
    try:
        response = session.get(f"https://ipwhois.app/json/{ip}", timeout=8)
        response.raise_for_status()
        data = response.json()

        if data.get("success", False):
            return data.get("country_code", "UNKNOWN").upper()
        else:
            logging.warning(f"查询 {ip} 国家信息失败：{data.get('message')}")
            return "UNKNOWN"
    except Exception as e:
        logging.error(f"获取国家信息失败 {ip} -> {e}")
        return "UNKNOWN"

# 从URL页面提取IP地址
def extract_ips_from_url(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36'
        }
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        # 正则直接匹配所有IP文本（效率高）
        matches = set(ip_pattern.findall(response.text))
        valid_matches = {ip for ip in matches if valid_ip(ip)}

        logging.info(f"从 {url} 提取到 {len(valid_matches)} 个唯一IP")
        return valid_matches

    except Exception as e:
        logging.error(f"请求失败 {url} -> {e}")
        return set()

# 主程序
def main():
    ip_addresses = set()

    for url in urls:
        ip_addresses.update(extract_ips_from_url(url))

    if not ip_addresses:
        logging.info("未提取到任何IP地址")
        return

    country_counter = defaultdict(int)
    sorted_ips = sorted(list(ip_addresses))

    with open("ip.txt", "w", encoding="utf-8", newline="\n") as file:
        for ip in sorted_ips:
            logging.info(f"查询国家信息：{ip}")
            country = get_ip_country(ip)
            country_counter[country] += 1
            file.write(f"{ip}#{country}{country_counter[country]}\n")
            sleep(0.15)  # 防止接口限制

    logging.info("✔ IP地址已保存到 ip.txt 文件中")


if __name__ == "__main__":
    main()
