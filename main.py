#!/usr/bin/env python3
# encoding: utf-8
"""
ProxyPool - SOCKS5 代理池一键工具

子命令：
    fetch   从公开源抓取 SOCKS5 代理，合并去重写入 socks.txt
    check   多线程检测 socks.txt 中代理存活性，写入 alive.txt
    serve   启动 HTTP 代理服务（上游随机选 SOCKS5），供 Burp 等使用
    run     一键全流程：fetch -> check -> serve

用法示例：
    python3 main.py fetch --proxy socks5://127.0.0.1:1080
    python3 main.py check --threads 100
    python3 main.py serve --port 8082
    python3 main.py run --proxy socks5://127.0.0.1:1080
"""

import argparse
import base64
import json
import os
import random
import re
import select
import signal
import socket
import threading
import time
import urllib.request
from collections import deque
from queue import Queue, Empty
from urllib.error import URLError

# ============================================================
# 共享配置
# ============================================================

# fetch 抓取源：均实测可达，返回纯文本 ip:port 列表
SOURCES = {
    "TheSpeedX": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "Monosans": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "ProxyScrape": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5"
                   "&timeout=10000&ssl=all&anonymity=all",
}

DEFAULT_SOCKS_FILE = "socks.txt"
DEFAULT_ALIVE_FILE = "alive.txt"
DEFAULT_REGION_FILE = "region.json"
CONFIG_FILE = "config.json"

# 配置默认值（启动/UI 未指定时使用）
CONFIG_DEFAULTS = {
    "listen": "127.0.0.1",
    "port": 8082,            # 代理端口（HTTP+SOCKS5 入站）
    "stats_port": 8083,      # 控制台端口
    "upstream_type": "socks5",
    "max_clients": 100,
    "fail_threshold": 3,
    "timeout": 6,
    "retries": 3,
    "threads": 100,          # check 线程数
    "fetch_proxy": "",       # fetch 时经由的代理（留空直连）
    "socks_file": DEFAULT_SOCKS_FILE,
    "alive_file": DEFAULT_ALIVE_FILE,
    "region_file": DEFAULT_REGION_FILE,
}
# 改动后需要重启监听 socket 的字段
RESTART_KEYS = ("listen", "port")


def _count_lines(path):
    """安全读取文件行数（去空行）。文件不存在返回 0。"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for l in f if l.strip())
    except OSError:
        return 0


class Config:
    """
    运行配置：持久化到 config.json，支持 UI/命令行覆盖。
    线程安全：所有读写加锁。
    """

    def __init__(self, path=CONFIG_FILE):
        self.path = path
        self.lock = threading.RLock()
        self.data = dict(CONFIG_DEFAULTS)
        self.load()

    def load(self):
        """从 config.json 读取，与默认值合并。"""
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                with self.lock:
                    for k in CONFIG_DEFAULTS:
                        if k in saved:
                            self.data[k] = saved[k]
        except (FileNotFoundError, ValueError):
            pass  # 首次运行或文件损坏，用默认值

    def save(self):
        """写回 config.json。"""
        with self.lock:
            data = dict(self.data)
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError as e:
            log.warn("保存 config.json 失败: {}".format(e))

    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)

    def get_all(self):
        with self.lock:
            return dict(self.data)

    def update(self, changes):
        """
        批量更新字段。返回 set(被改动的字段名)。
        调用方据返回值判断是否需要重启监听。
        """
        changed = set()
        with self.lock:
            for k, v in changes.items():
                if k in CONFIG_DEFAULTS and self.data.get(k) != v:
                    self.data[k] = v
                    changed.add(k)
        if changed:
            self.save()
        return changed

    def apply_overrides(self, overrides):
        """启动时用命令行参数覆盖（仅覆盖非 None 的项），不保存。"""
        with self.lock:
            for k, v in overrides.items():
                if v is not None and k in CONFIG_DEFAULTS:
                    self.data[k] = v

# IP:Port 合法性校验
PROXY_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})$")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def banner(title):
    print("\n" + "=" * 50)
    print("  " + title)
    print("=" * 50)


# 代理模式
MODES = ("auto", "sticky", "manual")


class Logger:
    """
    统一日志：同时输出到控制台与环形缓冲。
    缓冲供 Web 控制台 /logs 拉取。每条日志带递增序号，支持 ?since 增量查询。
    """

    def __init__(self, maxlen=500):
        self._buf = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0

    def log(self, msg, level="INFO"):
        line = "[{}] {}".format(level, msg)
        with self._lock:
            self._seq += 1
            self._buf.append((self._seq, level, msg))
        # 控制台输出（不影响缓冲）
        print(line)

    def info(self, msg):
        self.log(msg, "INFO")

    def warn(self, msg):
        self.log(msg, "WARN")

    def error(self, msg):
        self.log(msg, "ERROR")

    def snapshot(self, since=0):
        """返回序号 > since 的日志条目列表：[{seq, level, msg}]。"""
        with self._lock:
            return [{"seq": s, "level": lv, "msg": m}
                    for s, lv, m in self._buf if s > since]


# 全局日志实例（serve 及其工作线程共享）
log = Logger()


# ============================================================
# fetch 子命令：抓取聚合
# ============================================================

def _valid_proxy(line):
    """校验一行是否为合法 ip:port（含数值范围检查）。"""
    m = PROXY_RE.match(line.strip())
    if not m:
        return None
    octets = [int(x) for x in m.groups()[:4]]
    port = int(m.group(5))
    if any(o > 255 for o in octets) or not (1 <= port <= 65535):
        return None
    return "{}.{}.{}.{}:{}".format(*octets, port)


def _setup_urllib_proxy(proxy_url, logger=None):
    """
    如指定 --proxy，用 PySocks 把 urllib.request 走 SOCKS5。
    成功返回 True；无代理或失败返回 False（直连）。
    """
    lg = logger or log
    if not proxy_url:
        return False
    # 仅支持 socks5/socks4/http
    try:
        import socks  # PySocks
    except ImportError:
        lg.warn("未安装 PySocks，无法使用 --proxy，改为直连")
        return False

    m = re.match(r"^(socks5|socks5h|socks4|http)://([^:]+):(\d+)$", proxy_url)
    if not m:
        lg.warn("--proxy 格式错误，应为 socks5://host:port，改为直连")
        return False
    scheme, host, port = m.group(1), m.group(2), int(m.group(3))

    # 全局劫持 socket 的方式仅作用于本进程抓取阶段，且为单线程顺序抓取，可接受
    type_map = {"socks5": socks.PROXY_TYPE_SOCKS5, "socks5h": socks.PROXY_TYPE_SOCKS5,
                "socks4": socks.PROXY_TYPE_SOCKS4, "http": socks.PROXY_TYPE_HTTP}
    socks.set_default_proxy(type_map[scheme], host, port)
    socket.socket = socks.socksocket
    lg.info("抓取阶段经由代理 {}://{}:{}".format(scheme, host, port))
    return True


def fetch_from_source(name, url, timeout, logger=None):
    """抓单个源，返回合法代理列表。失败返回空列表。"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "ignore")
    except (URLError, socket.timeout, OSError) as e:
        if logger:
            logger.warn("{} 抓取失败: {}".format(name, e))
        return []

    found = []
    for line in raw.splitlines():
        v = _valid_proxy(line)
        if v:
            found.append(v)
    return found


def run_fetch(proxy=None, output=DEFAULT_SOCKS_FILE, timeout=20, overwrite=False,
              logger=None):
    """
    fetch 核心逻辑（供 CLI 与控制台共享）。
    返回 (总数, 新增数)。所有进度通过 logger 反馈。
    """
    lg = logger or log
    _setup_urllib_proxy(proxy, lg)

    existing = set()
    if os.path.exists(output) and not overwrite:
        with open(output, "r", encoding="utf-8", errors="ignore") as f:
            existing = {l.strip() for l in f if _valid_proxy(l)}
        lg.info("已有 {} 条: {}".format(len(existing), output))

    all_proxies = set(existing)
    for name, url in SOURCES.items():
        lg.info("抓取源: {}".format(name))
        got = fetch_from_source(name, url, timeout, lg)
        got = list(set(got))  # 源内去重
        lg.info("获取 {} 条 (去重后) from {}".format(len(got), name))
        all_proxies |= set(got)

    ordered = sorted(all_proxies)
    with open(output, "w", encoding="utf-8") as f:
        f.write("\n".join(ordered) + "\n")
    new = len(ordered) - len(existing)
    lg.info("写入 {} 共 {} 条 (新增 {} 条)".format(output, len(ordered), new))
    return len(ordered), new


def cmd_fetch(args):
    banner("FETCH - 抓取 SOCKS5 代理")
    run_fetch(proxy=args.proxy, output=args.output, timeout=args.timeout,
              overwrite=args.overwrite)


# ============================================================
# 地区查询（检测存活时顺带获取出口 IP 地区）
# ============================================================

# 经代理访问，拿出口 IP 的地区（这些站点返回的是"代理出口 IP"的地区）
REGION_URLS = [
    "http://www.cip.cc/",           # 返回 IP\t: x.x.x.x / 地址\t: 中国 xx xx
    "http://myip.ipip.net/",        # 返回 当前 IP：x 来自于：中国 xx xx
]
# 国家判定：地区字符串含这些关键词视为中国
CN_KEYWORDS = ("中国", "China", "CN", "中华")


def _parse_region(text):
    """
    从 cip.cc / myip.ipip.net 的响应文本提取地区字符串。
    返回地区字符串（如 '中国 广西 南宁'）或 None。
    严格过滤：结果不得含 HTML 标签、引号、尖括号等，长度合理。
    """
    if not text:
        return None
    # 若响应明显是 HTML 页面（含 <html/<head/<title 等），视为非预期格式
    if re.search(r"<\s*(html|head|title|script|meta)\b", text, re.I):
        return None

    def _clean(s):
        """清洗候选地区：去标签、去非法字符、校验长度。"""
        s = re.sub(r"<[^>]+>", "", s)  # 去任意 HTML 标签
        s = s.strip()
        # 合法地区只含中文、字母、空格、连字符；不含引号/尖括号/斜杠
        if not s:
            return None
        if re.search(r'[<>"\'=/\\]', s):
            return None
        if len(s) > 40 or len(s) < 2:
            return None
        return s

    # cip.cc 格式: "地址\t: 中国 广西 南宁"
    m = re.search(r"地址\s*:?\s*([^\n\r]+)", text)
    if m:
        region = _clean(m.group(1))
        if region:
            return region
    # myip.ipip.net 格式: "来自于：中国 广西 南宁  移动"
    m = re.search(r"来自于[：:]\s*([^\n\r]+)", text)
    if m:
        parts = _clean(m.group(1))
        if parts:
            # 去掉末尾运营商词，保留到市级
            words = parts.split()
            return " ".join(words[:3]) if words else None
    return None


def _country_of(region):
    """根据地区字符串判定国家代码：中国→CN，否则→OTHER。"""
    if not region:
        return "UNKNOWN"
    for kw in CN_KEYWORDS:
        if kw in region:
            return "CN"
    return "OTHER"


class RegionStore:
    """
    地区元数据存储：ip:port -> {region, country}。
    线程安全，持久化到 region.json。alive.txt 保持纯 ip:port 不变。
    """

    def __init__(self, path=DEFAULT_REGION_FILE):
        self.path = path
        self.lock = threading.Lock()
        self.data = {}
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict):
                self.data = d
        except (FileNotFoundError, ValueError):
            pass

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
        except OSError as e:
            log.warn("保存 region.json 失败: {}".format(e))

    def update(self, proxy, region):
        """更新单个代理地区。region 为 None 时记录为未知。"""
        with self.lock:
            self.data[proxy] = {"region": region or "未知", "country": _country_of(region)}

    def batch_save(self):
        with self.lock:
            self.save()

    def get(self, proxy):
        with self.lock:
            return self.data.get(proxy)

    def all(self):
        with self.lock:
            return dict(self.data)

    def remove(self, proxy):
        with self.lock:
            self.data.pop(proxy, None)

    def count_by_country(self):
        """返回 {CN: n, OTHER: n, UNKNOWN: n} 统计。"""
        with self.lock:
            cnt = {"CN": 0, "OTHER": 0, "UNKNOWN": 0}
            for v in self.data.values():
                c = v.get("country", "UNKNOWN")
                cnt[c] = cnt.get(c, 0) + 1
            return cnt


# ============================================================
# check 子命令：存活检测
# ============================================================

class ProxyChecker(threading.Thread):
    """多线程检测代理存活性，顺带通过代理获取出口地区。"""

    def __init__(self, check_queue, alive_list, lock, timeout, counters,
                 region_store, logger=None):
        threading.Thread.__init__(self)
        self.check_queue = check_queue
        self.alive_list = alive_list
        self.lock = lock
        self.timeout = timeout
        self.counters = counters  # {"done":0, "total":N} 共享计数
        self.region_store = region_store
        self.logger = logger

    def run(self):
        while True:
            try:
                target = self.check_queue.get_nowait()
            except Empty:
                return
            try:
                self.check_one(target)
            finally:
                self.check_queue.task_done()
                with self.lock:
                    self.counters["done"] += 1

    def check_one(self, proxy):
        proxies = {"http": "socks5://" + proxy, "https": "socks5://" + proxy}
        headers = {"User-Agent": UA, "Connection": "close"}
        try:
            import requests
            requests.packages.urllib3.disable_warnings()
            region = None
            # 优先通过代理访问地区站点（一举两得：验证存活 + 拿出口地区）
            for url in REGION_URLS:
                try:
                    r = requests.get(url, headers=headers, proxies=proxies,
                                     timeout=self.timeout, verify=False)
                    if r.status_code == 200:
                        region = _parse_region(r.text)
                        if region:
                            break
                except Exception:
                    continue
            # 若地区站点都失败，回退用 baidu 验证存活（地区未知）
            if region is None:
                try:
                    r = requests.get("http://www.baidu.com", headers=headers,
                                     proxies=proxies, timeout=self.timeout, verify=False)
                    if r.status_code != 200:
                        return  # 不存活
                except Exception:
                    return  # 不存活
            # 存活：记录 + 存地区
            with self.lock:
                self.alive_list.append(proxy)
            self.region_store.update(proxy, region)
            country = _country_of(region)
            tag = region if region else "未知地区"
            if self.logger:
                self.logger.info("存活: {}  [{}]".format(proxy, tag))
        except Exception:
            pass


def run_check(input_file=DEFAULT_SOCKS_FILE, output=DEFAULT_ALIVE_FILE,
              threads=100, timeout=3, logger=None, region_path=DEFAULT_REGION_FILE):
    """
    check 核心逻辑（供 CLI 与控制台共享）。
    检测存活时顺带通过代理获取出口地区，存入 region_path。
    返回 (存活数, 总数)。进度通过 logger 和返回值反馈。
    """
    lg = logger or log
    try:
        import requests  # noqa
    except ImportError:
        lg.error("需要 requests 库: pip install requests")
        return 0, 0

    # 读取并去重输入
    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            raw = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        lg.error("输入文件不存在: {}".format(input_file))
        return 0, 0
    uniq = list(set(raw))
    with open(input_file, "w", encoding="utf-8") as f:
        f.write("\n".join(uniq) + "\n")

    queue = Queue()
    for p in uniq:
        queue.put(p)
    total = len(uniq)
    lg.info("待检测 {} 条，线程数 {}（同时获取出口地区）".format(total, threads))

    alive_list = []
    lock = threading.Lock()
    counters = {"done": 0, "total": total}
    region_store = RegionStore(region_path)
    n_threads = min(threads, total) or 1
    pool_check = [ProxyChecker(queue, alive_list, lock, timeout, counters,
                               region_store, lg) for _ in range(n_threads)]
    for t in pool_check:
        t.start()
    for t in pool_check:
        t.join()

    with open(output, "w", encoding="utf-8") as f:
        f.write("\n".join(alive_list) + "\n")
    # 清理已不存活的地区记录，保存
    alive_set = set(alive_list)
    with region_store.lock:
        region_store.data = {k: v for k, v in region_store.data.items()
                             if k in alive_set}
        region_store.save()
    # 地区统计
    cc = region_store.count_by_country()
    lg.info("存活 {} / {} 条，已写入 {}（中国 {}，其他 {}，未知 {}）".format(
        len(alive_list), total, output, cc["CN"], cc["OTHER"], cc["UNKNOWN"]))
    return len(alive_list), total


def cmd_check(args):
    banner("CHECK - 检测代理存活性")
    run_check(input_file=args.input, output=args.output,
              threads=args.threads, timeout=args.timeout)


# ============================================================
# serve 子命令：HTTP 代理服务
# ============================================================

class ProxyPool:
    """
    线程安全的代理池：内存缓存、随机选取、运行时熔断、文件热加载、统计。

    熔断策略：单代理连续失败 fail_threshold 次即移出池子；成功一次即清零。
    热加载：pick() 前检查 alive.txt 的 mtime，变化则自动重新载入。
    """

    def __init__(self, path, fail_threshold=3, region_store=None, socks_file=None):
        self.path = path
        self.socks_file = socks_file or DEFAULT_SOCKS_FILE
        self.fail_threshold = fail_threshold
        self.region_store = region_store  # RegionStore 实例（可为 None）
        self.lock = threading.RLock()
        self.proxies = []                 # 当前可用 ip:port 列表
        self.fail_count = {}              # ip:port -> 连续失败次数
        self.removed = set()              # 本轮被熔断移除的代理（避免热加载后立刻加回）
        self._mtime = 0                   # 上次载入时的文件 mtime
        # 模式状态
        self.mode = "auto"                # auto / sticky / manual
        self.current = None               # 当前正在使用 / sticky 粘住的代理
        self.locked = None                # manual 模式锁定的代理
        # 地区过滤：None=不过滤, "CN"=仅中国, "OTHER"=仅非中国
        self.region_filter = None
        # 统计
        self.stat_requests = 0            # 总 pick 次数
        self.stat_success = 0             # 上游连接成功次数
        self.stat_fail = 0                # 上游连接失败次数
        self.stat_circuit_open = 0        # 触发熔断的代理数
        self.stat_reload = 0              # 热加载次数
        self.stat_rotate = 0              # 手动轮换次数
        self.load()

    def load(self):
        """从文件载入代理列表，保留当前熔断状态。"""
        try:
            st = os.stat(self.path)
            self._mtime = st.st_mtime
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                new = [l.strip() for l in f if _valid_proxy(l)]
        except FileNotFoundError:
            new = []
        with self.lock:
            # 合并：新列表中、且未被熔断的，纳入池子
            self.proxies = [p for p in new if p not in self.removed]
            # 清理已不在文件的失败计数
            self.fail_count = {p: c for p, c in self.fail_count.items() if p in new}
            # 清理已不在池中的 current/locked
            if self.current and self.current not in self.proxies:
                self.current = None
            if self.locked and self.locked not in self.proxies:
                self.locked = None
        if not self.proxies:
            log.warn("代理池为空 ({} 不存在或无有效行)".format(self.path))
        else:
            log.info("代理池载入 {} 条: {}".format(len(self.proxies), self.path))

    def _maybe_reload(self):
        """mtime 变化则重新载入。持锁调用前不锁，内部加锁。"""
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            return
        if mtime != self._mtime:
            log.info("检测到 {} 变更，热加载...".format(self.path))
            self.stat_reload += 1
            self.load()

    def _eligible(self, candidates):
        """
        按地区过滤候选列表。region_filter 为 None 时不过滤。
        无 region_store 或无记录的代理，过滤时不予剔除（宽松保留）。
        """
        rf = self.region_filter
        if not rf or not self.region_store:
            return candidates
        result = []
        for p in candidates:
            info = self.region_store.get(p)
            if info is None:
                result.append(p)  # 无地区记录，保留
            elif info.get("country") == rf:
                result.append(p)
        return result

    def pick(self):
        """
        按 mode 返回一个代理；池空返回 None。触发热加载检查。
        - auto:   每次随机（受地区过滤约束）
        - sticky: 优先复用 current（成功粘住的代理），失效则随机重选
        - manual: 固定返回 locked，被熔断则返回 None（不自动换）
        """
        self._maybe_reload()
        with self.lock:
            self.stat_requests += 1
            if not self.proxies:
                return None
            if self.mode == "manual":
                if self.locked and self.locked in self.proxies:
                    return self.locked
                return None  # 锁定的被熔断，不自动换
            if self.mode == "sticky":
                if self.current and self.current in self.proxies:
                    return self.current
                # current 失效，从符合地区的候选中随机重选并粘住
                cands = self._eligible(self.proxies) or self.proxies
                self.current = random.choice(cands)
                return self.current
            # auto：从符合地区的候选中随机
            cands = self._eligible(self.proxies) or self.proxies
            return random.choice(cands)

    def mark_success(self, proxy):
        """标记代理连接成功，清零失败计数；sticky 模式下粘住它。"""
        with self.lock:
            self.stat_success += 1
            self.fail_count.pop(proxy, None)
            if self.mode == "sticky":
                self.current = proxy

    def mark_fail(self, proxy):
        """
        标记代理连接失败。连续失败达阈值则移出池子（熔断）。
        返回 True 表示本次触发了熔断。
        """
        with self.lock:
            self.stat_fail += 1
            c = self.fail_count.get(proxy, 0) + 1
            self.fail_count[proxy] = c
            if c >= self.fail_threshold and proxy in self.proxies:
                try:
                    self.proxies.remove(proxy)
                except ValueError:
                    pass
                self.removed.add(proxy)
                self.stat_circuit_open += 1
                # 被熔断的若是 current/locked，清掉
                if self.current == proxy:
                    self.current = None
                if self.locked == proxy:
                    self.locked = None
                log.warn("[⚡熔断] {} 连续失败 {} 次，移出池子 (剩余 {})".format(
                    proxy, c, len(self.proxies)))
                return True
            return False

    def set_mode(self, mode):
        """切换模式。切到 manual 时自动锁定当前 current（若有）。"""
        if mode not in MODES:
            return False
        with self.lock:
            self.mode = mode
            if mode == "manual":
                # 锁定当前使用中的代理（优先 current）
                self.locked = self.current
            else:
                self.locked = None
        log.info("模式切换为: {}".format(mode))
        return True

    def set_region_filter(self, country):
        """设置地区过滤：None=全部, 'CN'=仅中国, 'OTHER'=仅非中国。"""
        if country not in (None, "CN", "OTHER"):
            return False
        with self.lock:
            self.region_filter = country
            # 切换过滤后清掉可能不符的 current
            if country and self.current:
                info = self.region_store.get(self.current) if self.region_store else None
                if info and info.get("country") != country:
                    self.current = None
        label = {None: "全部", "CN": "仅中国", "OTHER": "仅其他"}.get(country, str(country))
        log.info("地区过滤: {}".format(label))
        return True

    def rotate(self):
        """
        手动轮换到下一个随机代理（受地区过滤约束）。
        更新 current；manual 模式下同时更新 locked。返回新代理或 None。
        """
        self._maybe_reload()
        with self.lock:
            if not self.proxies:
                return None
            cands = self._eligible(self.proxies) or self.proxies
            # 尽量换一个不同的；只有 1 个候选时只能返回同一个
            if len(cands) > 1:
                choices = [p for p in cands if p != self.current]
                new = random.choice(choices) if choices else random.choice(cands)
            else:
                new = cands[0]
            self.current = new
            if self.mode == "manual":
                self.locked = new
            self.stat_rotate += 1
        log.info("[🔄轮换] 切换到 {}".format(new))
        return new

    def current_ip(self):
        """返回当前生效代理：manual 用 locked，否则用 current。"""
        with self.lock:
            if self.mode == "manual":
                return self.locked
            return self.current

    def stats(self):
        """返回统计快照（字典），含模式、当前代理、地区过滤与统计。"""
        with self.lock:
            cur = self.locked if self.mode == "manual" else self.current
            d = {
                "pool_size": len(self.proxies),         # 可用：存活且未熔断
                "removed": len(self.removed),            # 已熔断
                "requests": self.stat_requests,
                "success": self.stat_success,
                "fail": self.stat_fail,
                "circuit_open": self.stat_circuit_open,
                "reload": self.stat_reload,
                "rotate": self.stat_rotate,
                "mode": self.mode,
                "current": cur,
                "region_filter": self.region_filter,
            }
        # 抓取总数 / 存活总数（读文件，不随熔断变）
        d["socks_total"] = _count_lines(self.socks_file)
        d["alive_total"] = _count_lines(self.path)
        # 地区统计（来自 region_store，不加 pool 锁）
        if self.region_store:
            d["region_stats"] = self.region_store.count_by_country()
        return d

    def reset_circuits(self):
        """清除所有熔断状态，把移除的代理加回池子。"""
        with self.lock:
            self.proxies.extend(self.removed)
            self.removed.clear()
            self.fail_count.clear()
            n = len(self.proxies)
        log.info("熔断状态已重置，池子恢复至 {} 条".format(n))
        return n


class Header:
    """读取并解析客户端请求头。first 为协议识别阶段已读出的首字节（可省）。"""

    def __init__(self, conn, first=b""):
        self._method = None
        header = first
        try:
            while True:
                data = conn.recv(4096)
                header = b"%s%s" % (header, data)
                if header.endswith(b"\r\n\r\n") or not data:
                    break
        except Exception:
            pass
        self._header = header
        self.header_list = header.split(b"\r\n")
        self._host = None
        self._port = None

    def get_method(self):
        if self._method is None and b" " in self._header:
            self._method = self._header[:self._header.index(b" ")]
        return self._method

    def get_host_info(self):
        if self._host is None:
            method = self.get_method()
            line = self.header_list[0].decode("utf8", "ignore") if self.header_list else ""
            if method == b"CONNECT":
                host = line.split(" ")[1] if len(line.split(" ")) > 1 else ""
                host, port = (host.split(":") + [443])[:2] if ":" in host else (host, 443)
            else:
                host = ""
                for i in self.header_list:
                    if i.startswith(b"Host:"):
                        parts = i.split(b" ")
                        if len(parts) >= 2:
                            host = parts[1].decode("utf8", "ignore")
                            break
                if not host and "/" in line:
                    host = line.split("/")[2]
                host, port = (host.split(":") + [80])[:2] if ":" in host else (host, 80)
            self._host = host
            try:
                self._port = int(port)
            except ValueError:
                self._port = 80
        return self._host, self._port

    @property
    def data(self):
        return self._header

    def is_ssl(self):
        return self.get_method() == b"CONNECT"


def _relay(s1, s2):
    """单向转发 s1 -> s2，直到任一端断开。"""
    try:
        while True:
            data = s1.recv(4096)
            if not data:
                return
            s2.sendall(data)
    except Exception:
        pass
    finally:
        try:
            s1.shutdown(socket.SHUT_RD)
        except Exception:
            pass


def _pipe(a, b):
    """双向转发 a <-> b（两个单向线程）。"""
    t1 = threading.Thread(target=_relay, args=(a, b), daemon=True)
    t2 = threading.Thread(target=_relay, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


# 上游代理类型 -> PySocks 常量（延迟到 _connect_via_proxy 内 import）
_UPSTREAM_TYPES = {
    "socks5": "PROXY_TYPE_SOCKS5",
    "socks4": "PROXY_TYPE_SOCKS4",
    "http": "PROXY_TYPE_HTTP",
}


def _connect_via_proxy(upstream_type, proxy_host, proxy_port,
                       dest_host, dest_port, timeout):
    """
    通过指定上游代理建立到 dest 的连接（局部 socket，不污染全局）。
    支持 socks5 / socks4 / http。
    """
    import socks  # PySocks
    type_attr = _UPSTREAM_TYPES.get(upstream_type)
    if type_attr is None:
        raise ValueError("不支持的上游类型: {}".format(upstream_type))
    ptype = getattr(socks, type_attr)
    s = socks.socksocket()
    s.set_proxy(ptype, proxy_host, proxy_port)
    s.settimeout(timeout)
    s.connect((dest_host, dest_port))
    return s


def _socks5_handshake(client, first_byte):
    """
    完成 SOCKS5 入站握手（无认证）。返回 (dest_host, dest_port) 或 None。
    first_byte 为已读出的首字节（应为 0x05）。
    """
    try:
        # --- 1. 协商认证方式 ---
        # 客户端: VER(1) NMETHODS(1) METHODS(NMETHODS)
        nmethods = client.recv(1)
        if not nmethods:
            return None
        client.recv(ord(nmethods))  # 丢弃 METHODS 列表
        # 服务端: VER(1) METHOD(1) —— 0x00 = 无需认证
        client.sendall(b"\x05\x00")

        # --- 2. 读取请求 ---
        # VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
        ver = client.recv(1)
        if not ver or ver != b"\x05":
            return None
        cmd = client.recv(1)
        client.recv(1)  # RSV
        atyp = client.recv(1)
        if not atyp:
            return None

        atyp = ord(atyp)
        if atyp == 1:        # IPv4
            addr = socket.inet_ntoa(client.recv(4))
        elif atyp == 3:      # 域名
            ln = client.recv(1)
            if not ln:
                return None
            addr = client.recv(ord(ln)).decode("utf-8", "ignore")
        elif atyp == 4:      # IPv6
            addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")  # 不支持 ATYP
            return None

        port_bytes = client.recv(2)
        if len(port_bytes) < 2:
            return None
        port = (ord(port_bytes[0:1]) << 8) | ord(port_bytes[1:2])

        # 仅支持 CONNECT (0x01)
        if ord(cmd) != 0x01:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # 不支持 CMD
            return None

        return addr, port
    except Exception:
        return None


def _socks5_reply_ok(client):
    """告知客户端 SOCKS5 连接已建立。"""
    # VER(05) REP(00=成功) RSV(00) ATYP(01=IPv4) BND.ADDR(4) BND.PORT(2)
    client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")


def _establish_upstream(pool, dest_host, dest_port, timeout, max_retries, upstream_type):
    """
    尝试用池中代理建立到目标的连接，失败反馈给池子用于熔断。
    成功返回 (server_socket, proxy_used)，全失败返回 (None, None)。
    """
    server = None
    for _ in range(max_retries):
        proxy = pool.pick()
        if proxy is None:
            log.warn("代理池为空，放弃")
            return None, None
        ph, pp = proxy.split(":")[0], int(proxy.split(":")[1])
        try:
            server = _connect_via_proxy(upstream_type, ph, pp,
                                        dest_host, dest_port, timeout)
            pool.mark_success(proxy)
            log.info("via {}://{}:{}".format(upstream_type, ph, pp))
            return server, proxy
        except Exception as e:
            pool.mark_fail(proxy)
            log.warn("{} 失败: {}".format(proxy, e))
            try:
                if server:
                    server.close()
            except Exception:
                pass
            server = None
            continue
    log.error("重试 {} 次均失败".format(max_retries))
    return None, None


def handle_client(client, pool, timeout, max_retries, upstream_type):
    """
    处理单个客户端连接：自动识别入站协议（SOCKS5 或 HTTP），
    再经上游代理建立隧道并双向转发。
    """
    client.settimeout(timeout)

    # 读首字节用于协议识别（带缓冲，HTTP 路径要复用已读数据）
    first = client.recv(1)
    if not first:
        client.close()
        return

    if first == b"\x05":
        # ===== SOCKS5 入站 =====
        dest = _socks5_handshake(client, first)
        if dest is None:
            client.close()
            return
        dest_host, dest_port = dest
        log.info(">> SOCKS5 {} {}".format(dest_host, dest_port))
        server, _ = _establish_upstream(pool, dest_host, dest_port,
                                        timeout, max_retries, upstream_type)
        if server is None:
            # 连接失败：REP=0x05（连接被拒绝）
            try:
                client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            except Exception:
                pass
            client.close()
            return
        _socks5_reply_ok(client)
    else:
        # ===== HTTP 入站（首字节需回填到 Header 读取流）=====
        header = Header(client, first)
        if not header.data:
            client.close()
            return
        dest_host, dest_port = header.get_host_info()
        method = header.get_method()
        log.info(">> {} {} {}".format(method.decode("utf8", "ignore") if method else "?",
                                      dest_host, dest_port))
        server, _ = _establish_upstream(pool, dest_host, dest_port,
                                        timeout, max_retries, upstream_type)
        if server is None:
            client.close()
            return
        try:
            if header.is_ssl():
                client.sendall(b"HTTP/1.0 200 Connection Established\r\n\r\n")
            else:
                server.sendall(header.data)
        except Exception:
            for s in (server, client):
                try:
                    s.close()
                except Exception:
                    pass
            return

    # 双向转发（SOCKS5 与 HTTP 共用）
    try:
        _pipe(client, server)
    except Exception:
        pass
    finally:
        for s in (server, client):
            try:
                s.close()
            except Exception:
                pass


def _web_html_path():
    """返回控制台 HTML 路径：优先 web/index.html（相对 main.py 目录）。"""
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "web", "index.html")


class TaskManager:
    """
    管理 fetch / check 异步任务：单实例，同一时刻每种任务只允许一个在跑。
    提供状态查询供控制台 /task 拉取。
    """

    def __init__(self, pool, logger):
        self.pool = pool
        self.logger = logger
        self.lock = threading.Lock()
        # task_type -> state dict
        self.tasks = {"fetch": self._blank(), "check": self._blank()}

    @staticmethod
    def _blank():
        return {"running": False, "start": 0, "end": 0,
                "status": "idle", "result": None}

    def _snapshot(self, t):
        with self.lock:
            s = dict(self.tasks[t])
        return s

    def snapshot(self):
        return {"fetch": self._snapshot("fetch"), "check": self._snapshot("check")}

    def start(self, task_type, fn):
        """若该任务空闲则后台启动 fn()，返回 True；已在跑返回 False。"""
        with self.lock:
            if self.tasks[task_type]["running"]:
                return False
            self.tasks[task_type] = {
                "running": True, "start": time.time(), "end": 0,
                "status": "running", "result": None,
            }

        def runner():
            t = task_type
            try:
                rv = fn()
                with self.lock:
                    self.tasks[t]["status"] = "done"
                    self.tasks[t]["result"] = rv
            except Exception as e:
                self.logger.error("{} 任务异常: {}".format(t, e))
                with self.lock:
                    self.tasks[t]["status"] = "error"
                    self.tasks[t]["result"] = str(e)
            finally:
                with self.lock:
                    self.tasks[t]["running"] = False
                    self.tasks[t]["end"] = time.time()

        threading.Thread(target=runner, daemon=True).start()
        return True


def _start_control_server(pool, logger, listen, port, conf, taskmgr, request_restart=None):
    """启动控制台 + 状态 API（标准库 http.server）。"""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import json

    html_path = _web_html_path()

    class ControlHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass  # 静默

        def _send(self, code, body, ctype="application/json"):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                self.wfile.write(data)
            except Exception:
                pass

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False), "application/json")

        def _read_body(self):
            ln = int(self.headers.get("Content-Length", 0) or 0)
            return self.rfile.read(ln) if ln else b""

        def do_GET(self):
            raw = self.path
            path = raw.split("?", 1)[0]
            query = raw.split("?", 1)[1] if "?" in raw else ""

            if path == "/" or path == "/index.html":
                # 控制台页面
                try:
                    with open(html_path, "r", encoding="utf-8") as f:
                        self._send(200, f.read(), "text/html; charset=utf-8")
                except FileNotFoundError:
                    self._send(404, "控制台页面缺失: web/index.html", "text/plain")
                return
            if path == "/pool.html":
                # 代理池管理页面
                pool_html = os.path.join(os.path.dirname(html_path), "pool.html")
                try:
                    with open(pool_html, "r", encoding="utf-8") as f:
                        self._send(200, f.read(), "text/html; charset=utf-8")
                except FileNotFoundError:
                    self._send(404, "管理页缺失: web/pool.html", "text/plain")
                return
            if path == "/stats":
                st = pool.stats()
                st.update(conf.get_all())  # 注入运行配置
                self._json(st)
                return
            if path == "/config":
                self._json(conf.get_all())
                return
            if path == "/count":
                self._json({"pool_size": len(pool.proxies),
                            "removed": len(pool.removed)})
                return
            if path == "/logs":
                since = 0
                for kv in query.split("&"):
                    if kv.startswith("since="):
                        try:
                            since = int(kv.split("=")[1])
                        except ValueError:
                            pass
                self._json({"logs": logger.snapshot(since)})
                return
            if path == "/reload":
                pool.load()
                self._json(pool.stats())
                return
            if path == "/reset":
                pool.reset_circuits()
                self._json(pool.stats())
                return
            if path == "/task":
                self._json(taskmgr.snapshot())
                return
            if path == "/pool":
                # 返回池中代理详情：ip:port、地区、国家、状态（活跃/已熔断）
                with pool.lock:
                    active = set(pool.proxies)
                    removed = set(pool.removed)
                    fail_count = dict(pool.fail_count)
                regions = pool.region_store.all() if pool.region_store else {}
                items = []
                # 活跃代理
                for p in sorted(active):
                    info = regions.get(p, {})
                    items.append({
                        "proxy": p, "region": info.get("region", "未知"),
                        "country": info.get("country", "UNKNOWN"),
                        "status": "active", "fails": fail_count.get(p, 0),
                    })
                # 已熔断代理
                for p in sorted(removed):
                    info = regions.get(p, {})
                    items.append({
                        "proxy": p, "region": info.get("region", "未知"),
                        "country": info.get("country", "UNKNOWN"),
                        "status": "removed", "fails": fail_count.get(p, 0),
                    })
                self._json({
                    "total": len(items),
                    "active": len(active),
                    "removed": len(removed),
                    "socks_total": _count_lines(pool.socks_file),
                    "alive_total": _count_lines(pool.path),
                    "items": items,
                })
                return
            self._send(404, '{"error":"not found"}', "application/json")

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            body = self._read_body()
            try:
                data = json.loads(body.decode("utf-8")) if body else {}
            except ValueError:
                data = {}

            if path == "/mode":
                mode = data.get("mode")
                if pool.set_mode(mode):
                    self._json(pool.stats())
                else:
                    self._json({"error": "无效模式，可选: " + "/".join(MODES)}, 400)
                return
            if path == "/region":
                # 设置地区过滤：country = None / "CN" / "OTHER"
                country = data.get("country")
                if country == "" or country == "ALL":
                    country = None
                if pool.set_region_filter(country):
                    self._json(pool.stats())
                else:
                    self._json({"error": "无效地区，可选: ALL / CN / OTHER"}, 400)
                return
            if path == "/pool/delete":
                # 从 alive.txt 和池中移除指定代理
                target = (data.get("proxy") or "").strip()
                if not target:
                    self._json({"error": "缺少 proxy 参数"}, 400)
                    return
                alive_path = conf.get("alive_file", DEFAULT_ALIVE_FILE)
                try:
                    with open(alive_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [l.strip() for l in f if l.strip()]
                    lines = [l for l in lines if l != target]
                    with open(alive_path, "w", encoding="utf-8") as f:
                        f.write("\n".join(lines) + "\n")
                except OSError as e:
                    self._json({"error": "写文件失败: " + str(e)}, 500)
                    return
                with pool.lock:
                    if target in pool.proxies:
                        pool.proxies.remove(target)
                    pool.removed.discard(target)
                if pool.region_store:
                    pool.region_store.remove(target)
                logger.info("[管理] 删除代理 {}".format(target))
                self._json({"removed": target, "pool_size": len(pool.proxies)})
                return
            if path == "/rotate":
                new = pool.rotate()
                if new is None:
                    self._json({"error": "代理池为空"}, 400)
                else:
                    self._json(pool.stats())
                return
            if path == "/fetch":
                # 优先用请求传入的 proxy，否则用 config 里的 fetch_proxy
                proxy = data.get("proxy") or conf.get("fetch_proxy") or None
                socks_path = conf.get("socks_file", DEFAULT_SOCKS_FILE)
                started = taskmgr.start("fetch", lambda: run_fetch(
                    proxy=proxy, output=socks_path, logger=logger))
                if started:
                    logger.info("[任务] fetch 已启动" + ("" if not proxy else " via " + proxy))
                    self._json(taskmgr.snapshot()["fetch"])
                else:
                    self._json({"error": "fetch 任务正在运行中"}, 409)
                return
            if path == "/check":
                threads = int(data.get("threads") or conf.get("threads") or 100)
                timeout = int(data.get("timeout") or 3)
                alive_path = conf.get("alive_file", DEFAULT_ALIVE_FILE)
                socks_path = conf.get("socks_file", DEFAULT_SOCKS_FILE)
                region_path = conf.get("region_file", DEFAULT_REGION_FILE)

                def do_check():
                    n_alive, n_total = run_check(
                        input_file=socks_path, output=alive_path,
                        threads=threads, timeout=timeout, logger=logger,
                        region_path=region_path)
                    # 完成后让 serve 热加载新的 alive.txt 和地区数据
                    if pool.region_store:
                        pool.region_store.load()
                    pool.load()
                    return {"alive": n_alive, "total": n_total}

                started = taskmgr.start("check", do_check)
                if started:
                    logger.info("[任务] check 已启动 (threads={})".format(threads))
                    self._json(taskmgr.snapshot()["check"])
                else:
                    self._json({"error": "check 任务正在运行中"}, 409)
                return
            self._send(404, '{"error":"not found"}', "application/json")

        def do_PUT(self):
            path = self.path.split("?", 1)[0]
            body = self._read_body()
            try:
                data = json.loads(body.decode("utf-8")) if body else {}
            except ValueError:
                data = {}

            if path == "/config":
                # 类型转换：数值字段转 int
                int_fields = {"port", "stats_port", "max_clients",
                              "fail_threshold", "timeout", "retries", "threads"}
                cleaned = {}
                for k, v in data.items():
                    if k in int_fields:
                        try:
                            v = int(v)
                        except (ValueError, TypeError):
                            continue
                    if k in CONFIG_DEFAULTS:
                        cleaned[k] = v
                if not cleaned:
                    self._json({"error": "无有效字段"}, 400)
                    return
                changed = conf.update(cleaned)
                logger.info("[配置] 更新字段: {}".format(", ".join(sorted(changed)) or "无变化"))
                # 若改了 listen/port，触发 serve 重启监听
                need_restart = bool(changed & set(RESTART_KEYS))
                if need_restart and request_restart:
                    logger.info("[配置] 监听端口变更，触发重启...")
                    request_restart()
                resp = conf.get_all()
                resp["_changed"] = sorted(changed)
                resp["_restart"] = need_restart
                self._json(resp)
                return
            self._send(404, '{"error":"not found"}', "application/json")

    try:
        httpd = HTTPServer((listen, port), ControlHandler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    except Exception as e:
        logger.error("控制台启动失败: {}".format(e))


def cmd_serve(args):
    """serve 子命令：启动代理服务 + 控制台。配置来自 config.json，命令行参数可覆盖。"""
    banner("SERVE - HTTP/SOCKS5 代理服务")
    try:
        import socks  # noqa
    except ImportError:
        log.error("需要 PySocks 库: pip install PySocks")
        return

    # 加载配置：config.json 为基础，命令行参数覆盖（仅非默认值）
    cfg = Config()
    overrides = {}
    # 判断命令行是否显式指定（与 CONFIG_DEFAULTS 不同的视为显式指定）
    if args.listen != "127.0.0.1":
        overrides["listen"] = args.listen
    if args.port != 8082:
        overrides["port"] = args.port
    if args.upstream_type != "socks5":
        overrides["upstream_type"] = args.upstream_type
    if args.max_clients != 100:
        overrides["max_clients"] = args.max_clients
    if args.fail_threshold != 3:
        overrides["fail_threshold"] = args.fail_threshold
    if args.timeout != 6:
        overrides["timeout"] = args.timeout
    if args.retries != 3:
        overrides["retries"] = args.retries
    if getattr(args, "threads", 100) != 100:
        overrides["threads"] = args.threads
    if args.stats_port not in (0, 8083):
        overrides["stats_port"] = args.stats_port
    if args.file != DEFAULT_ALIVE_FILE:
        overrides["alive_file"] = args.file
    cfg.apply_overrides(overrides)

    upstream_type = cfg.get("upstream_type")
    if upstream_type not in _UPSTREAM_TYPES:
        log.error("不支持的上游类型: {} (可选: {})".format(
            upstream_type, "/".join(_UPSTREAM_TYPES)))
        return

    region_store = RegionStore(cfg.get("region_file", DEFAULT_REGION_FILE))
    pool = ProxyPool(cfg.get("alive_file"), fail_threshold=cfg.get("fail_threshold"),
                     region_store=region_store, socks_file=cfg.get("socks_file"))
    if not pool.proxies:
        log.error("代理池为空，请在控制台点击「抓取代理」「检测存活」，或命令行运行 fetch+check")
        # 不 return：仍启动控制台，让用户从 UI 抓代理

    # 并发上限信号量（按配置的 max_clients）
    sem = threading.BoundedSemaphore(cfg.get("max_clients"))

    # 运行时控制标志
    state = {"running": True, "restart": False}

    def request_restart():
        state["restart"] = True

    # 控制台（始终启动，便于从 UI 配置/抓代理）
    stats_port = cfg.get("stats_port")
    if stats_port:
        taskmgr = TaskManager(pool, log)
        _start_control_server(pool, log, cfg.get("listen"), stats_port,
                              cfg, taskmgr, request_restart)
    else:
        taskmgr = None

    listen_addr = cfg.get("listen")
    proxy_port = cfg.get("port")

    def make_socket():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_addr, proxy_port))
        sock.listen(100)
        return sock

    s = make_socket()
    log.info("监听 {}:{} (支持HTTP+SOCKS5 入站，最大并发 {}，熔断阈值 {})".format(
        listen_addr, proxy_port,
        cfg.get("max_clients"), cfg.get("fail_threshold")))
    log.info("客户端测试命令:\n curl -x http://{}:{}/ http://cip.cc \n curl --socks5-hostname {}:{} http://cip.cc".format(
        listen_addr, proxy_port, listen_addr, proxy_port))
    if stats_port:
        log.info("控制台: http://{}:{}/  (Ctrl+C 退出)".format(listen_addr, stats_port))

    def worker(conn):
        # 每次连接读取 config 最新值，UI 改动立即对新连接生效
        try:
            handle_client(conn, pool, cfg.get("timeout"),
                          cfg.get("retries"), cfg.get("upstream_type"))
        finally:
            sem.release()

    # 信号处理：Ctrl+C 干净退出（Windows 下配合 select 轮询可靠）
    def _on_sigint(signum, frame):
        state["running"] = False
        log.info("收到退出信号，正在停止...")

    prev_handler = signal.signal(signal.SIGINT, _on_sigint)

    try:
        while state["running"]:
            # 检测热重启（UI 改了 listen/port）
            if state["restart"]:
                state["restart"] = False
                new_listen = cfg.get("listen")
                new_port = cfg.get("port")
                log.info("重启监听: {} -> {}:{}".format(
                    (listen_addr, proxy_port), new_listen, new_port))
                try:
                    s.close()
                except Exception:
                    pass
                listen_addr, proxy_port = new_listen, new_port
                try:
                    s = make_socket()
                    log.info("[√] 新监听 {}:{}".format(listen_addr, proxy_port))
                except OSError as e:
                    log.error("新端口监听失败: {}，保留旧配置".format(e))
                    # 回退：尝试恢复原值并重新绑定
                    cfg.update({"listen": listen_addr, "port": proxy_port})
                    s = make_socket()
                continue

            # select 超时轮询：每 0.5s 醒一次，便于响应 restart / Ctrl+C
            try:
                r, _, _ = select.select([s], [], [], 0.5)
            except (OSError, ValueError):
                break
            if s in r:
                try:
                    conn, addr = s.accept()
                except OSError:
                    break
                if not sem.acquire(blocking=False):
                    cur_max = cfg.get("max_clients")
                    log.warn("并发已达上限 {}，拒绝连接".format(cur_max))
                    conn.close()
                    continue
                t = threading.Thread(target=worker, args=(conn,), daemon=True)
                t.start()
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGINT, prev_handler)
        try:
            s.close()
        except Exception:
            pass
        log.info("serve 已停止")


# ============================================================
# run 子命令：一键全流程
# ============================================================

def cmd_run(args):
    banner("RUN - 一键全流程")
    # 1. fetch
    fetch_ns = argparse.Namespace(
        proxy=args.proxy, output=args.socks, timeout=args.timeout, overwrite=False)
    cmd_fetch(fetch_ns)
    # 2. check
    check_ns = argparse.Namespace(
        input=args.socks, output=args.alive, threads=args.threads, timeout=args.timeout)
    cmd_check(check_ns)
    # 3. serve (阻塞)
    serve_ns = argparse.Namespace(
        listen=args.listen, port=args.port, file=args.alive,
        timeout=args.timeout, retries=args.retries,
        max_clients=args.max_clients, fail_threshold=args.fail_threshold,
        upstream_type=args.upstream_type, stats_port=args.stats_port)
    cmd_serve(serve_ns)


# ============================================================
# argparse 入口
# ============================================================

def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="ProxyPool - SOCKS5 代理池一键工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="子命令: fetch / check / serve / run",
    )
    sub = p.add_subparsers(dest="command")

    # fetch
    pf = sub.add_parser("fetch", help="从公开源抓取 SOCKS5 代理")
    pf.add_argument("--proxy", help="抓取经由的代理，如 socks5://127.0.0.1:1080")
    pf.add_argument("--output", default=DEFAULT_SOCKS_FILE, help="输出文件 (默认 %(default)s)")
    pf.add_argument("--timeout", type=int, default=20, help="抓取超时秒 (默认 %(default)s)")
    pf.add_argument("--overwrite", action="store_true", help="覆盖输出文件而非合并")
    pf.set_defaults(func=cmd_fetch)

    # check
    pc = sub.add_parser("check", help="多线程检测代理存活性")
    pc.add_argument("--input", default=DEFAULT_SOCKS_FILE, help="输入文件 (默认 %(default)s)")
    pc.add_argument("--output", default=DEFAULT_ALIVE_FILE, help="输出文件 (默认 %(default)s)")
    pc.add_argument("--threads", type=int, default=100, help="线程数 (默认 %(default)s)")
    pc.add_argument("--timeout", type=int, default=3, help="检测超时秒 (默认 %(default)s)")
    pc.set_defaults(func=cmd_check)

    # serve
    ps = sub.add_parser("serve", help="启动 HTTP 代理服务")
    ps.add_argument("--listen", default="127.0.0.1", help="监听地址 (默认 %(default)s)")
    ps.add_argument("--port", type=int, default=8082, help="监听端口 (默认 %(default)s)")
    ps.add_argument("--file", default=DEFAULT_ALIVE_FILE, help="代理池文件 (默认 %(default)s)")
    ps.add_argument("--timeout", type=int, default=6, help="连接超时秒 (默认 %(default)s)")
    ps.add_argument("--retries", type=int, default=3, help="单连接最大重试 (默认 %(default)s)")
    ps.add_argument("--max-clients", type=int, default=100, dest="max_clients",
                    help="最大并发客户端连接 (默认 %(default)s)")
    ps.add_argument("--fail-threshold", type=int, default=3, dest="fail_threshold",
                    help="熔断阈值：连续失败此次数后移出池子 (默认 %(default)s)")
    ps.add_argument("--upstream-type", default="socks5", dest="upstream_type",
                    choices=list(_UPSTREAM_TYPES.keys()),
                    help="上游代理类型 (默认 %(default)s)")
    ps.add_argument("--stats-port", type=int, default=0, dest="stats_port",
                    help="状态 API 端口，0=不启用 (默认 %(default)s)")
    ps.set_defaults(func=cmd_serve)

    # run
    pr = sub.add_parser("run", help="一键全流程 fetch->check->serve")
    pr.add_argument("--proxy", help="fetch 阶段经由的代理")
    pr.add_argument("--listen", default="127.0.0.1", help="serve 监听地址 (默认 %(default)s)")
    pr.add_argument("--port", type=int, default=8082, help="serve 监听端口 (默认 %(default)s)")
    pr.add_argument("--socks", default=DEFAULT_SOCKS_FILE, help="socks 列表文件")
    pr.add_argument("--alive", default=DEFAULT_ALIVE_FILE, help="alive 列表文件")
    pr.add_argument("--threads", type=int, default=100, help="check 线程数 (默认 %(default)s)")
    pr.add_argument("--timeout", type=int, default=6, help="超时秒 (默认 %(default)s)")
    pr.add_argument("--retries", type=int, default=3, help="serve 重试次数 (默认 %(default)s)")
    pr.add_argument("--max-clients", type=int, default=100, dest="max_clients",
                    help="serve 最大并发 (默认 %(default)s)")
    pr.add_argument("--fail-threshold", type=int, default=3, dest="fail_threshold",
                    help="serve 熔断阈值 (默认 %(default)s)")
    pr.add_argument("--upstream-type", default="socks5", dest="upstream_type",
                    choices=list(_UPSTREAM_TYPES.keys()),
                    help="上游代理类型 (默认 %(default)s)")
    pr.add_argument("--stats-port", type=int, default=0, dest="stats_port",
                    help="状态 API 端口，0=不启用 (默认 %(default)s)")
    pr.set_defaults(func=cmd_run)

    return p


USAGE_TEXT = """\
ProxyPool - 自动轮换 IP 的代理池，带 Web 控制台

  最简用法（推荐）：
    python3 main.py serve          # 启动服务，浏览器开 http://127.0.0.1:8083/ 操作一切

  子命令：
    serve    启动代理服务 + Web 控制台（抓取/检测/模式切换/改配置全在网页里）
    fetch    抓取公开免费代理到 socks.txt
    check    多线程检测代理存活性，写入 alive.txt
    run      一键全流程：fetch → check → serve

  连接代理（端口默认 8082，HTTP/SOCKS5 自动识别）：
    curl -x http://127.0.0.1:8082 http://httpbin.org/ip
    curl --socks5-hostname 127.0.0.1:8082 http://httpbin.org/ip

  详细参数：python3 main.py <命令> -h
"""


def main():
    parser = build_parser()
    args = parser.parse_args()
    # 无子命令时显示简洁用法（不报错）
    if not getattr(args, "command", None):
        print(USAGE_TEXT)
        return
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
