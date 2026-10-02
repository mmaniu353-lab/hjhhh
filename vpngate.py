#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线
============================
流程:
  1. 并发合并官方 HTTPS CSV、GitHub 镜像与 24 小时内已发布的候选节点
  2. 只保留「带 TCP 入口」的中继 = SSTP 可用节点
     (OpenVPN 配置里 proto tcp + remote <ip> <port>; UDP-only 中继无法走 SSTP/xray 链, 直接丢弃)
  3. 按 host+port+protocol 去重
  4. 并发调用已部署的 Cloudflare Worker:  GET {WORKER}/check?proxyip=host:port
     (单节点 HTTP 成功 != 节点可用; 以 Worker 返回 JSON 的 success 字段为准)
  5. 保留 success=true 的节点, 按国家分组, 生成 public/data.json + public/index.html
  6. 网页端 (GitHub Pages) 读取 data.json 展示

退出码:
  0 = 正常完成 (允许部分节点检测失败)
  1 = 硬性失败 (数据源全挂 / 解析不出 SSTP 节点 / Worker 完全不可达 / 程序异常)
     这些情况绝不允许"假成功"
"""

import base64
import csv
import io
import hashlib
import ipaddress
import socket
import json
import math
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests
import yaml

# 保证日志在任何控制台编码下都能输出 (Windows GBK 控制台不会崩)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置 (均可用环境变量覆盖, 便于本地测试)
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "https://www.vpngate.net/api/iphone/")
# 独立补充数据源: 预解析 JSON 镜像 (字段与官方 CSV 同源)
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
# 已部署的 Cloudflare Worker 检测接口 (GET /check?proxyip=host:port, 实测确认)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://ch.opopoiovcc.kdns.fr/check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "8")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "45"))
VERIFY_PASSES = max(1, int(os.environ.get("VERIFY_PASSES", "2")))
SITE_URL = os.environ.get("SITE_URL", "https://mmaniu353-lab.github.io/hjhhh").rstrip("/")
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))         # 0=不限; 本地测试可设小值
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))              # 拉取数据源超时
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")
PREVIOUS_MAX_AGE_SECONDS = 24 * 60 * 60
PREVIOUS_MAX_CANDIDATES = 512

# 出口数据中心的关键词启发 (判断"是否住宅 IP"用, 页面标注为估算)
DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
# 常见住宅宽带运营商关键词
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

# ISO 国家码 -> 中文名 (edgetunnel 清单展示用; 未收录则回退英文原名)
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# ---------------------------------------------------------------------------
# 日志 (用户要求的分区格式)
# ---------------------------------------------------------------------------
_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    """硬性失败: 明确报错并退出非 0, 绝不允许假成功。"""
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 第 1 步: 获取 VPN Gate 原始节点
# ---------------------------------------------------------------------------
def fetch_vpngate():
    """Merge independent discovery sources; all candidates still enter current verification.

    Previous Pages results only supply addresses, never successful checks or exit evidence.
    Source order is deterministic so duplicate candidates retain official source metadata.
    """
    sources = [
        ("vpngate.net/api/iphone", VPNGATE_API, lambda response: parse_csv(response.text)),
        ("github-mirror", VPNGATE_MIRROR, lambda response: parse_mirror_json(response.json())),
        ("previous-pages", SITE_URL + "/data.json", lambda response: parse_previous_json(response.json())),
    ]

    def fetch_source(name, url, parser):
        try:
            log("VPN GATE", f"获取 {name}: {url}")
            response = requests.get(url, timeout=HTTP_TIMEOUT,
                                    headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
            response.raise_for_status()
            rows = parser(response)
            log("VPN GATE", f"{name}: {len(rows)} 个候选节点")
            return rows
        except Exception as exc:
            log("VPN GATE", f"{name} 获取失败: {exc}")
            return []

    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = [pool.submit(fetch_source, *source) for source in sources]
        fetched = [future.result() for future in futures]
    rows = [row for batch in fetched for row in batch]
    if not rows:
        die("VPN Gate 官方 API、镜像与有效期内的历史候选均不可用 (不生成空结果, 本次运行判定失败)")
    return rows, "+".join(source[0] for source, batch in zip(sources, fetched) if batch)


def parse_csv(text):
    """解析官方 CSV。表头行含 'HostName'; 按列名映射, 列名缺失时用固定位置回退。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    # 列名映射 (不假设固定位置, 列名变化时自动适配; 全缺失时回退到已知位置)
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {"hostname": idx.get("hostname", 0),
           "ip": idx.get("ip", 1),
           "countrylong": idx.get("countrylong", 5),
           "countryshort": idx.get("countryshort", 6),
           "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1)}

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) <= max(pos.values()):
            continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows


def parse_mirror_json(data):
    """解析 GitHub 镜像 JSON: [ { "servers": [ {hostname, ip, countrylong, countryshort, openvpn_configdata_base64} ] } ]"""
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        if not isinstance(s, dict):
            continue
        host = s.get("hostname") or s.get("host") or ""
        ip = s.get("ip") or ""
        if not isinstance(host, str) or not isinstance(ip, str):
            continue
        host, ip = host.strip(), ip.strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows


def parse_previous_json(data):
    """Use at most 512 fresh own Pages addresses as unverified discovery candidates."""
    if not isinstance(data, dict) or not isinstance(data.get("available"), list):
        return []
    try:
        generated = datetime.strptime(data.get("generated_at", ""), "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return []
    age = (datetime.now(timezone.utc) - generated).total_seconds()
    if not 0 <= age <= PREVIOUS_MAX_AGE_SECONDS:
        return []
    rows, seen = [], set()
    for previous in data["available"]:
        if not isinstance(previous, dict) or previous.get("success") is not True or previous.get("protocol") != "sstp":
            continue
        candidate = {"host": previous.get("host"), "ip": previous.get("ip"),
                     "country_long": previous.get("country"), "country_short": previous.get("country_code"),
                     "config_b64": "", "sstp_port": previous.get("port")}
        validated = to_sstp_nodes([candidate])
        if not validated:
            continue
        node = validated[0]
        key = (node["host"], node["port"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(candidate)
        if len(rows) >= PREVIOUS_MAX_CANDIDATES:
            break
    return rows


# ---------------------------------------------------------------------------
# 第 2 步: 筛选 SSTP 节点 (只保留带 TCP 入口的中继)
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.opengw\.net)?", re.I | re.ASCII)


def to_sstp_nodes(rows):
    """Validate candidates, using TCP config or an explicit previous SSTP port.
    Return only addresses and source geography; historical check evidence is discarded.
    """
    nodes = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        host, ip = r.get("host"), r.get("ip")
        if not isinstance(host, str) or not isinstance(ip, str):
            continue
        host, ip = host.strip().lower(), ip.strip()
        if not _HOST_RE.fullmatch(host):
            continue
        try:
            if not ipaddress.ip_address(ip).is_global:
                continue
        except ValueError:
            continue
        if "sstp_port" in r:
            value = r["sstp_port"]
            if type(value) is int:
                port = value
            elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value):
                port = int(value)
            else:
                continue
        else:
            try:
                cfg = base64.b64decode(r.get("config_b64") or "", validate=False).decode("utf-8", "replace")
            except (ValueError, TypeError):
                continue
            if not _PROTO_TCP_RE.search(cfg):
                continue
            match = _REMOTE_RE.search(cfg)
            if not match or len(match.group(1)) > 5:
                continue
            port = int(match.group(1))
        if not 1 <= port <= 65535:
            continue
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        country = r.get("country_long")
        code = r.get("country_short")
        country = country.strip() if isinstance(country, str) else ""
        code = code.strip().upper() if isinstance(code, str) else ""
        code = code if re.fullmatch(r"[A-Z]{2}", code) else ""
        nodes.append({
            "host": host,
            "port": port,
            "ip": ip,
            "country": country,
            "country_code": code,
        })
    return nodes


def dedupe(nodes):
    """按 host+port+protocol 去重。"""
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


# ---------------------------------------------------------------------------
# 第 3 步: 并发调用 Cloudflare Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    """住宅/机房分类, 按可信度排序:
    1) Worker 返回的真实 is_datacenter 标志 (IP 情报库);
    2) 出口 ASN 组织名关键词;
    3) host 前缀启发式 (最后兜底, 属估算)。"""
    # 1) 真实数据中心标志 (SSTP 版 Worker 顶层 exit 直接给出)
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    # 2) 出口组织名关键词
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    # 3) host 前缀启发式 (估算)
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"      # VPN Gate 官方公共中继 (机房/托管)
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"     # 数字编号 = 注册的家用宽带中继 (家宽, 估算)
    return "unknown"


def check_one(node, session):
    """调用 Worker 检测单节点。返回节点+检测结果的合并 dict。
    单节点失败 (网络错误/非 200/坏 JSON) 不会抛出, 统一记 success=False。"""
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["success"] = False
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        if not isinstance(j, dict):
            raise ValueError("Checker response must be an object")
        ok = j.get("success") is True
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        if not ok:
            return out
        # SSTP 版 Worker: 顶层直接返回 exit, 含真实 is_datacenter 标志 + 嵌套 asn 对象
        exit_info = j.get("exit")
        if not isinstance(exit_info, dict):
            raise ValueError("Checker did not return valid exit information")
        exit_address = ipaddress.ip_address(exit_info.get("ip") or "")
        if not exit_address.is_global:
            raise ValueError("Checker did not return a public exit IP")
        if exit_info:
            asn = exit_info.get("asn") or {}
            if not isinstance(asn, dict):
                raise ValueError("Checker returned invalid ASN information")
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        out["success"] = True
        out["status"] = "success"
        return out
    except Exception as exc:
        out["success"] = False
        out["status"] = "failed"
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out


def check_stable_node(node):
    """Each node owns its HTTP session; only consecutive passes with a stable exit qualify."""
    checks = []
    with requests.Session() as session:
        for _ in range(VERIFY_PASSES):
            result = check_one(node, session)
            result["verification_passes"] = len(checks)
            if not result.get("success"):
                return result
            try:
                ipaddress.ip_address((result.get("exit") or {}).get("ip") or "")
            except (ValueError, TypeError, AttributeError):
                result.update(success=False, status="failed", error="Verification requires a valid exit IP")
                return result
            if checks and (checks[0].get("exit") or {}).get("ip") != (result.get("exit") or {}).get("ip"):
                result.update(success=False, status="failed", error="Exit IP changed during consecutive checks")
                return result
            checks.append(result)
    result = checks[-1]
    result["verification_passes"] = len(checks)
    delays = [check["latency_ms"] for check in checks if isinstance(check.get("latency_ms"), (int, float))]
    if delays:
        result["latency_ms"] = max(delays)
    return result


def check_all(nodes, session=None):
    """Check candidates with separate sessions and require repeated successful connections."""
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_stable_node, n) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


# ---------------------------------------------------------------------------
# 第 4 步: 生成网页数据
# ---------------------------------------------------------------------------
def https_latency_key(node):
    """Order by actual HTTPS chain latency; absent/invalid measurements always come last."""
    delay = node.get("https_latency_ms")
    valid = type(delay) in (int, float) and math.isfinite(delay) and delay >= 0
    return (not valid, delay if valid else 0, node.get("host") or "", node.get("port") or 0)


def build_outputs(results, raw_count, sstp_count, source):
    available = [dict(r) for r in results if r.get("success") is True]
    countries = {}
    for n in available:
        exit_info = n.get("exit")
        if isinstance(exit_info, dict):
            code = exit_info.get("country_code")
            code = code.strip().upper() if isinstance(code, str) else ""
            if re.fullmatch(r"[A-Z]{2}", code):
                n["country_code"] = code
                country = exit_info.get("country")
                n["country"] = country.strip() if isinstance(country, str) and country.strip() else COUNTRY_ZH.get(code, code)
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }

    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=https_latency_key)
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data


CHAIN_URL = os.environ.get("CHAIN_URL", SITE_URL + "/chains.txt")


def node_name(node, country_name=None):
    code = str(node.get("country_code") or "?").upper()
    country = COUNTRY_ZH.get(code) or country_name or code
    kind = "住宅" if node.get("residential") == "residential" else "机房"
    identity = f"{node['host'].lower()}:{node['port']}"
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:8]
    return f"{country}-{kind}-{suffix}"


def build_chains_text(data):
    """名字绑定 host:port，不会因为排序变化而指向另一出口。"""
    countries = data["countries"]
    lines = [
        "# VPN Gate SSTP 节点 -> edgetunnel 链式代理清单",
        f"# 自动更新: {data['generated_at']} (计划每 15 分钟重新检测，GitHub 可能延迟)",
        f"# 固定地址: {CHAIN_URL}",
        "#",
        "# 用法: 在 edgetunnel 节点备注里直接粘贴下面任意一行 (名字与指令连写)",
        "#   例: 日本-住宅-1234abcd$sstp://vpn:vpn@vpnxxx.opengw.net:443",
        "# 名字绑定节点地址; 自动故障切换请使用 mihomo.yaml 订阅",
        "# 账号密码固定 vpn:vpn ; 端口必须保留",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                *https_latency_key(n),
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            lines.append(f"{node_name(n, zh)}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            lines.append(f"{node_name(n, zh)}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# 可选的用户指定入口；默认使用自有 Worker 域名解析出的 Cloudflare IPv4。
# 可通过环境变量 EDGE_HOSTS 覆盖 (逗号分隔)
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "",
    ).split(",")
    if h.strip()
]

HOSTS_URL = os.environ.get("HOSTS_URL", SITE_URL + "/hosts.txt")


def build_hosts_text(data):
    """生成可直接粘贴到 edgetunnel 后台「自定义优选IP」框的清单。
    每行 = 入口地址#名字$sstp://... ; 名字绑定 SSTP 节点。"""
    countries = data["countries"]
    # 仅使用自有域名的地址；可用 HOSTS_ENTRY 覆盖(逗号分隔)。
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = [e.strip() for e in _entry.split(",") if e.strip()] or EDGE_HOSTS or [f"{ip}:443" for ip in get_entry_addresses()]
    lines = [
        "# edgetunnel「自定义优选IP」清单 (整段复制, 追加到后台现有内容后面)",
        f"# 自动更新: {data['generated_at']} (计划每 15 分钟重新检测，GitHub 可能延迟)",
        f"# 固定地址: {HOSTS_URL}",
        "# 每行 = 入口地址#名字$sstp://vpn:vpn@节点:端口",
        "# 默认入口是自有 Worker 的 Cloudflare IPv4，避免额外域名依赖",
        "# 名字 = 国家-住宅/机房-地址摘要, 直接区分住宅与机房",
        "# 名字绑定节点地址; 自动故障切换请使用 mihomo.yaml 订阅",
        "# 账号密码固定 vpn:vpn ; 节点端口必须保留",
        "# ========================================================",
    ]
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                *https_latency_key(n),
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{node_name(n, zh)}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{node_name(n, zh)}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel 完整订阅 (vless://) 配置
EDT_UUID = os.environ.get("EDT_UUID", "5ed92fca-0651-4f04-958b-ff71f5469df4")
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "fgfg.opopoiovcc.kdns.fr")
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT", "chrome")
SUB_URL = os.environ.get("SUB_URL", SITE_URL + "/sub.txt")


def _b64_secret_encode(plaintext, secret):
    """复刻 edgetunnel 的 base64SecretEncode: UTF-8 循环密钥 XOR + 标准 base64。"""
    data = plaintext.encode("utf-8")
    key = secret.encode("utf-8")
    mixed = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return base64.b64encode(mixed).decode("ascii")


def _socks5_account(address, default_port=80):
    """复刻 edgetunnel 的 获取SOCKS5账号: user:pass@host:port -> {username,password,hostname,port}。"""
    address = re.sub(r"^(socks5|http|https|turn|sstp)://", "", address.strip(), flags=re.I).split("#")[0].strip()
    at = address.rfind("@")
    auth, hostpart = (address[:at], address[at + 1:]) if at != -1 else ("", address)
    hostpart = hostpart.split("/")[0]
    username = password = None
    if auth:
        if ":" not in auth:
            try:
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode("utf-8")
            except Exception:
                pass
        parts = auth.split(":", 1)
        username = parts[0]
        password = parts[1] if len(parts) > 1 else None
    hostname, port = hostpart, default_port
    if hostpart.count(":") == 1 and not hostpart.startswith("["):
        h, p = hostpart.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)
    return {"username": username, "password": password, "hostname": hostname, "port": port}


def build_sub_text(data):
    """生成 edgetunnel 完整 vless:// 订阅 (链式代理编码在 path)。
    填进 edgetunnel 后台「订阅链接」URL, 客户端定时拉取即可自动轮换。"""
    countries = data["countries"]
    lines = [
        "# edgetunnel 完整订阅 (vless://) —— 填进后台「订阅链接」URL",
        f"# 自动更新: {data['generated_at']} (计划每 15 分钟重新检测，GitHub 可能延迟)",
        f"# 固定地址: {SUB_URL}",
        f"# 节点域名: {EDT_DOMAIN} (传输 ws / TLS / fingerprint {EDT_FINGERPRINT})",
        "# 名字绑定节点地址; 自动故障切换请使用 mihomo.yaml 订阅",
        "# 账号密码固定 vpn:vpn ; 节点端口已编码进 path",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                *https_latency_key(n),
            ),
        )
        for i, n in enumerate(nodes, 1):
            name = node_name(n, zh)
            chain = {"type": "sstp", **_socks5_account(f"vpn:vpn@{n['host']}:{n['port']}", 443)}
            chain_json = json.dumps(chain, separators=(",", ":"))
            enc = _b64_secret_encode(chain_json, EDT_UUID)
            path = quote("/video/" + enc, safe="")
            link = (
                f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
                f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
                f"&path={path}&encryption=none&alpn=#{quote(name, safe='')}"
            )
            lines.append(link)
    return "\n".join(lines) + "\n"


def get_entry_addresses():
    """Only resolve our own front-door hostname; the client can dial these literal IPv4 addresses."""
    override = os.environ.get("EDT_ENTRY_IPS", "").strip()
    if override:
        addresses = [str(ipaddress.IPv4Address(value.strip())) for value in override.split(",")]
    else:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(EDT_DOMAIN, 443, socket.AF_INET, socket.SOCK_STREAM)})
    if not addresses:
        raise RuntimeError("Could not resolve own Cloudflare entry; previous deployment is preserved")
    return addresses


def build_mihomo_config(data):
    """Strict residential profile plus a renewable provider; no public traffic falls back to DIRECT."""
    nodes = sorted([n for n in data["available"] if n.get("residential") == "residential"],
                   key=https_latency_key)
    proxies = []
    entries = get_entry_addresses()
    for index, node in enumerate(nodes):
        verified_entry = node.get("entry_address")
        entry = verified_entry if verified_entry in entries else entries[index % len(entries)]
        proxies.append(build_proxy(node, entry))
    codes = sorted({n["country_code"] for n in nodes}, key=lambda code: (code != "JP", code))
    groups = []
    for code in codes:
        country = COUNTRY_ZH.get(code) or code
        group = {"name": country + "住宅自动", "type": "url-test" if code == "JP" else "fallback", "use": ["住宅节点"],
                       "proxies": ["REJECT"],
                       "filter": "^" + re.escape(country) + "-住宅-", "empty-fallback": "REJECT",
                       "url": "https://1.1.1.1/", "expected-status": 301,
                       "interval": 120 if code == "JP" else 180, "timeout": 15000, "max-failed-times": 2,
                       "lazy": False, "disable-udp": True}
        if code == "JP":
            group["tolerance"] = 100
            groups.append(dict(group, name="日本住宅稳定", type="fallback"))
            groups[-1].pop("tolerance", None)
        groups.append(group)
    choices = [g["name"] for g in groups]
    groups.insert(0, {"name": "住宅出口", "type": "select", "proxies": choices or ["REJECT"],
                      "use": ["住宅节点"], "empty-fallback": "REJECT", "disable-udp": True})
    bootstrap = ["https://223.5.5.5/dns-query#name-cert-verify=dns.alidns.com", "https://1.1.1.1/dns-query"]
    cfg = {
        "mixed-port": 2087, "allow-lan": False, "mode": "rule", "ipv6": False,
        "log-level": "warning", "unified-delay": True, "tcp-concurrent": True,
        "keep-alive-interval": 20, "profile": {"store-selected": True, "store-fake-ip": True},
        "tun": {"enable": True, "stack": "mixed", "auto-route": True, "auto-detect-interface": True,
                "strict-route": True, "dns-hijack": ["any:53", "tcp://any:53"], "mtu": 1400},
        "dns": {"enable": True, "listen": "127.0.0.1:1053", "ipv6": False, "prefer-h3": False,
                "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16", "respect-rules": True,
                "default-nameserver": bootstrap, "proxy-server-nameserver": bootstrap,
                "direct-nameserver": bootstrap, "nameserver": ["tcp://8.8.4.4:53#住宅出口"],
                "fallback": [], "use-system-hosts": False, "fake-ip-filter": ["*.lan", "*.local", "localhost"]},
        "proxy-providers": {"住宅节点": {"type": "http", "url": SITE_URL + "/proxies.yaml",
                            "path": "./providers/hjhhh-residential.yaml", "interval": 900, "proxy": "DIRECT",
                            "health-check": {"enable": True, "url": "https://1.1.1.1/",
                                             "expected-status": 301, "interval": 120, "timeout": 15000, "lazy": False}}},
        "proxy-groups": groups,
        "rules": ["AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
                  "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
                  "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
                  "MATCH,住宅出口"],
    }
    return cfg, {"proxies": proxies}


def build_proxy(node, entry):
    chain = {"type": "sstp", **_socks5_account(f"vpn:vpn@{node['host']}:{node['port']}", 443)}
    path = "/video/" + _b64_secret_encode(json.dumps(chain, separators=(",", ":")), EDT_UUID)
    return {"name": node_name(node), "type": "vless", "server": entry,
            "port": 443, "uuid": EDT_UUID, "tls": True, "udp": False,
            "servername": EDT_DOMAIN, "skip-cert-verify": False,
            "client-fingerprint": EDT_FINGERPRINT, "network": "ws",
            "ws-opts": {"path": path, "headers": {"Host": EDT_DOMAIN}}}


def verify_end_to_end(results):
    binary = os.environ.get('MIHOMO_BINARY', '').strip()
    if not binary:
        log('HTTPS END TO END', '未配置 MIHOMO_BINARY，跳过完整链路验证；生产 workflow 必须配置')
        return results
    from end_to_end import verify_nodes
    return verify_nodes(results, binary)


def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    # 固定网页: 始终用 web/index.html 模板生成同一个 index.html (数据来自 data.json)
    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = ("<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
                "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
                "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # edgetunnel 链式代理清单 (固定 URL, 方案一: 名字不变、指令自动换)
    chains_path = os.path.join(PUBLIC_DIR, "chains.txt")
    with open(chains_path, "w", encoding="utf-8") as f:
        f.write(build_chains_text(data))

    # 可直接粘贴进后台「自定义优选IP」框的清单 (入口地址#名字$sstp://...)
    hosts_path = os.path.join(PUBLIC_DIR, "hosts.txt")
    with open(hosts_path, "w", encoding="utf-8") as f:
        f.write(build_hosts_text(data))

    # 完整 vless:// 订阅 (填进后台「订阅链接」URL, 客户端自动轮换)
    sub_path = os.path.join(PUBLIC_DIR, "sub.txt")
    with open(sub_path, "w", encoding="utf-8") as f:
        f.write(build_sub_text(data))
    config, pool = build_mihomo_config(data)
    for filename, value in [("mihomo.yaml", config), ("proxies.yaml", pool)]:
        with open(os.path.join(PUBLIC_DIR, filename), "w", encoding="utf-8") as f:
            yaml.safe_dump(value, f, allow_unicode=True, sort_keys=False)
    return data_path, html_path, chains_path, hosts_path, sub_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()

    # 1) 数据源
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    # 2) SSTP 筛选 + 去重
    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = sorted(uniq, key=lambda node: node["country_code"] != "JP")[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    # 3) 并发检测
    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    results = verify_end_to_end(results)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    # 硬性失败: Worker 完全不可达 (没有任何一个请求拿到正常响应)
    if not success:
        die("没有节点通过连续检测 — 本次运行失败，保留上一次已部署的订阅")
    if not any(node.get("residential") == "residential" for node in success):
        die("没有住宅估算节点通过连续检测 — 保留上次住宅订阅，不发布空代理集合")

    # 4) 结果 + 网页
    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    data_path, html_path, chains_path, hosts_path, sub_path = write_outputs(data)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(chains_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(hosts_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(sub_path, REPO_DIR)}")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
