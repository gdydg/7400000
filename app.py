import os
import requests
from bs4 import BeautifulSoup
import base64
import re
import urllib.parse
import json
from datetime import datetime, timedelta
import pytz
from playwright.sync_api import sync_playwright
from flask import Flask, jsonify, Response
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
OUTPUT_FILE = 'output/extracted_ids.txt'
ROUTE_STATE_FILE = 'output/decoded_routes.jsonl'
LAST_RUN_TIME = "尚未执行"

# ==========================================
# 核心：内置轻量级 XXTEA 解密算法
# ==========================================
def str2long(s, w):
    v = []
    for i in range(0, len(s), 4):
        v0 = s[i]
        v1 = s[i+1] if i+1 < len(s) else 0
        v2 = s[i+2] if i+2 < len(s) else 0
        v3 = s[i+3] if i+3 < len(s) else 0
        v.append(v0 | (v1 << 8) | (v2 << 16) | (v3 << 24))
    if w:
        v.append(len(s))
    return v

def long2str(v, w):
    vl = len(v)
    if vl == 0: return b""
    n = (vl - 1) << 2
    if w:
        m = v[-1]
        if (m < n - 3) or (m > n): return None
        n = m
    s = bytearray()
    for i in range(vl):
        s.append(v[i] & 0xff)
        s.append((v[i] >> 8) & 0xff)
        s.append((v[i] >> 16) & 0xff)
        s.append((v[i] >> 24) & 0xff)
    return bytes(s[:n]) if w else bytes(s)

def xxtea_decrypt(data, key):
    if not data: return b""
    v = str2long(data, False)
    k = str2long(key, False)
    if len(k) < 4:
        k.extend([0] * (4 - len(k)))
    n = len(v) - 1
    if n < 1: return b""
    
    z = v[n]
    y = v[0]
    delta = 0x9E3779B9
    q = 6 + 52 // (n + 1)
    sum_val = (q * delta) & 0xffffffff
    
    while sum_val != 0:
        e = (sum_val >> 2) & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_val ^ y) + (k[(p & 3) ^ e] ^ z))
            y = v[p] = (v[p] - mx) & 0xffffffff
        z = v[n]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_val ^ y) + (k[(0 & 3) ^ e] ^ z))
        y = v[0] = (v[0] - mx) & 0xffffffff
        sum_val = (sum_val - delta) & 0xffffffff
        
    return long2str(v, True)

def decode_stream_from_id(raw_id):
    """将抓取到的 ID 解密为直播源 URL，失败返回 None。"""
    target_key = b"ABCDEFGHIJKLMNOPQRSTUVWX"
    try:
        decoded_id = urllib.parse.unquote(raw_id)
        pad = 4 - (len(decoded_id) % 4)
        if pad != 4:
            decoded_id += "=" * pad
        bin_data = base64.b64decode(decoded_id)
        decrypted_bytes = xxtea_decrypt(bin_data, target_key)
        if not decrypted_bytes:
            return None
        json_str = decrypted_bytes.decode('utf-8', errors='ignore')
        data = json.loads(json_str)
        return data.get("url")
    except Exception:
        return None

def normalize_route_text(text):
    """归一化线路文本，便于匹配“信1/信①/信号”等变体。"""
    if not text:
        return ""
    return re.sub(r'\s+', '', text.strip())

def pick_signal_label(dd):
    """
    从线路节点中选择“带有信字”的标签。
    只要任一 span.diss 文本包含“信”即视为目标线路。
    """
    labels = [normalize_route_text(span.get_text()) for span in dd.select('span.diss')]
    labels = [label for label in labels if label]
    for label in labels:
        if '信' in label:
            return label
    return None

def extract_paps_ids_from_text(text):
    """从文本中提取 paps.html?id= 后面的 id。"""
    if not text:
        return []
    return re.findall(r'paps\.html\?id=([^"\'&\s]+)', text)

def collect_paps_ids_from_page_assets(page):
    """
    从网页资产文件路径中提取 paps.html?id=... 的 id：
    仅扫描 src/href/data-src 等资源路径本身，不解析页面源码和 JS 文件内容。
    """
    ids = set()

    try:
        assets = page.evaluate("""
            () => {
                const out = [];
                document.querySelectorAll('[src],[href],[data-src]').forEach(el => {
                    const src = el.getAttribute('src');
                    const href = el.getAttribute('href');
                    const dataSrc = el.getAttribute('data-src');
                    if (src) out.push(src);
                    if (href) out.push(href);
                    if (dataSrc) out.push(dataSrc);
                });
                return out;
            }
        """)
    except Exception:
        assets = []

    for raw in assets:
        if not raw or raw.startswith('javascript:'):
            continue
        abs_url = urllib.parse.urljoin(page.url, raw)
        for item in extract_paps_ids_from_text(abs_url):
            ids.add(item)

    return list(ids)

def get_keep_window(now, tz):
    """保留窗口：前一天 20:00:00 到当天 23:59:59。"""
    yesterday = (now - timedelta(days=1)).date()
    today = now.date()
    keep_start = tz.localize(datetime.combine(yesterday, datetime.min.time().replace(hour=20)))
    keep_end = tz.localize(datetime.combine(today, datetime.max.time().replace(microsecond=0)))
    return keep_start, keep_end

def load_existing_records(now, tz):
    """加载历史成功记录，并按照保留窗口过滤。"""
    keep_start, keep_end = get_keep_window(now, tz)
    records = []
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith('{'):
                    continue
                try:
                    item = json.loads(line)
                    item_match_time = item.get("match_time")
                    if not item_match_time:
                        continue
                    match_time = datetime.strptime(item_match_time, "%Y-%m-%d %H:%M:%S")
                    match_time = tz.localize(match_time)
                    if keep_start <= match_time <= keep_end and item.get("source_url") and item.get("stream_url"):
                        records.append(item)
                except Exception:
                    continue
    return records

def load_route_states(now, tz):
    """加载线路解密状态，并清理保留窗口外数据。"""
    keep_start, keep_end = get_keep_window(now, tz)
    states = {}
    if os.path.exists(ROUTE_STATE_FILE):
        with open(ROUTE_STATE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    source_url = item.get("source_url")
                    match_time_str = item.get("match_time")
                    if not source_url or not match_time_str:
                        continue
                    match_time = tz.localize(datetime.strptime(match_time_str, "%Y-%m-%d %H:%M:%S"))
                    if keep_start <= match_time <= keep_end:
                        states[source_url] = item
                except Exception:
                    continue
    return states

def save_route_states(states):
    os.makedirs('output', exist_ok=True)
    with open(ROUTE_STATE_FILE, 'w', encoding='utf-8') as f:
        for item in states.values():
            f.write(json.dumps(item, ensure_ascii=False) + '\n')

# ==========================================
# 爬虫任务逻辑
# ==========================================
def scrape_job():
    global LAST_RUN_TIME
    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz)
    LAST_RUN_TIME = now.strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{LAST_RUN_TIME}] 开始执行抓取任务...")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        res = requests.get('https://www.74001.tv', headers=headers, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')
    except Exception as e:
        print(f"获取主页失败: {e}")
        return

    # 存储比赛基础信息：match_id -> info_dict
    match_infos = {}
    # 抓取窗口：前4小时到后1小时
    lower_bound = now - timedelta(hours=4)
    upper_bound = now + timedelta(hours=1)

    for a in soup.select('a.clearfix'):
        href = a.get('href')
        time_str = a.get('t-nzf-o')
        if href and '/bofang/' in href and time_str:
            try:
                if len(time_str) == 10:
                    time_str += " 00:00:00"
                match_time = tz.localize(datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S'))
                
                if lower_bound <= match_time <= upper_bound:
                    match_id = href.split('/')[-1]
                    
                    em_tag = a.select_one('.eventtime em')
                    league = em_tag.text.strip() if em_tag else "未知联赛"
                    
                    zhudui_tag = a.select_one('.zhudui p')
                    home = zhudui_tag.text.strip() if zhudui_tag else "未知主队"
                    
                    kedui_tag = a.select_one('.kedui p')
                    away = kedui_tag.text.strip() if kedui_tag else "未知客队"
                    
                    time_i_tag = a.select_one('.eventtime i')
                    display_time = time_i_tag.text.strip() if time_i_tag else match_time.strftime('%H:%M')
                    
                    match_infos[match_id] = {
                        'match_time': match_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'time': display_time,
                        'league': league,
                        'home': home,
                        'away': away
                    }
            except Exception:
                continue

    # 存储内页原始播放链接映射：play_url -> info_dict（仅保留带“信”线路）
    play_url_to_info = {}
    for match_id, info in match_infos.items():
        link = f"https://www.74001.tv/live/{match_id}"
        try:
            res = requests.get(link, headers=headers, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
            for dd in soup.select('dd[nz-g-c]'):
                signal_label = pick_signal_label(dd)
                if not signal_label:
                    continue
                b64_str = dd.get('nz-g-c')
                if b64_str:
                    decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                    m = re.search(r'ftp:\*\*(.*?)(?:::|$)', decoded)
                    if m:
                        raw_url = m.group(1)
                        url = 'http://' + raw_url.replace('!', '.').replace('&nbsp', 'com').replace('*', '/')
                        info_with_route = dict(info)
                        info_with_route['route_label'] = signal_label
                        play_url_to_info[url] = info_with_route
        except Exception as e:
            continue

    existing_records = load_existing_records(now, tz)
    route_states = load_route_states(now, tz)

    for url, info in play_url_to_info.items():
        old = route_states.get(url, {})
        route_states[url] = {
            "source_url": url,
            "match_time": info["match_time"],
            "time": info["time"],
            "league": info["league"],
            "home": info["home"],
            "away": info["away"],
            "route_label": info.get("route_label", ""),
            "resolved": old.get("resolved", False),
            "id": old.get("id"),
            "stream_url": old.get("stream_url")
        }

    success_by_source_url = {
        source_url for source_url, state in route_states.items()
        if state.get("resolved") and state.get("stream_url")
    }

    final_data = []
    for source_url in success_by_source_url:
        state = route_states[source_url]
        if state.get("id") and state.get("stream_url"):
            final_data.append({
                'id': state["id"],
                'source_url': source_url,
                'stream_url': state["stream_url"],
                'match_time': state["match_time"],
                'time': state["time"],
                'league': state["league"],
                'home': state["home"],
                'away': state["away"],
                'route_label': state.get("route_label", "")
            })

    for item in existing_records:
        if item["source_url"] not in success_by_source_url:
            final_data.append(item)
            success_by_source_url.add(item["source_url"])
            
    seen_ids = set()
    seen_source_urls = set(success_by_source_url)

    for item in final_data:
        if item.get("id"):
            seen_ids.add(item["id"])

    # ====== 核心修复区：Playwright 资源管理 ======
    with sync_playwright() as p:
        # 增加关键参数：--disable-dev-shm-usage 和 --disable-gpu
        browser = p.chromium.launch(
            headless=True, 
            args=[
                '--no-sandbox', 
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu'
            ]
        )
        
        for url, info in play_url_to_info.items():
            if url in success_by_source_url:
                continue
                
            # 每次请求新建独立的上下文和页面，防止事件监听叠加
            context = browser.new_context()
            page = context.new_page()
            
            try:
                page.goto(url, wait_until='networkidle', timeout=15000)
                page.wait_for_timeout(1500)
                # 仅从源码/资产路径抽取 id（不再监听 request）
                candidate_ids = collect_paps_ids_from_page_assets(page)
                
                for extracted_id in candidate_ids:
                    if extracted_id not in seen_ids and url not in seen_source_urls:
                        stream_url = decode_stream_from_id(extracted_id)
                        if stream_url:
                            route_states[url]["resolved"] = True
                            route_states[url]["id"] = extracted_id
                            route_states[url]["stream_url"] = stream_url
                            final_data.append({
                                'id': extracted_id,
                                'source_url': url,
                                'stream_url': stream_url,
                                'match_time': info['match_time'],
                                'time': info['time'],
                                'league': info['league'],
                                'home': info['home'],
                                'away': info['away'],
                                'route_label': info.get('route_label', '')
                            })
                            seen_ids.add(extracted_id)
                            seen_source_urls.add(url)
                    if url in seen_source_urls:
                        break
            except Exception as e:
                print(f"解析页面失败 {url}: {e}")
                continue
            finally:
                # 强制释放资源
                page.close()
                context.close()
                
        browser.close()
    # ==========================================

    os.makedirs('output', exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for item in final_data:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    save_route_states(route_states)
    print(f"任务完成，共保存 {len(final_data)} 个独立字符。")

# ==========================================
# 统一的播放列表生成逻辑
# ==========================================
def generate_playlist(fmt="m3u", mode="clean"):
    if not os.path.exists(OUTPUT_FILE):
        return "请稍后再试，爬虫尚未生成数据"
        
    with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
    
    if fmt == "m3u":
        content = "#EXTM3U\n"
    else:
        content = "体育直播,#genre#\n"
        
    index = 1
    
    for line in lines:
        try:
            if line.startswith('{'):
                item = json.loads(line)
                channel_name = f"{item['time']} {item['home']}VS{item['away']}"
                group_title = "体育直播"
                stream_url = item.get("stream_url")
            else:
                channel_name = f"体育直播 {index}"
                group_title = "体育直播"
                stream_url = decode_stream_from_id(line)

            if stream_url:
                if mode == "plus":
                    stream_url = f"{stream_url}|Referer="

                if fmt == "m3u":
                    content += f'#EXTINF:-1 group-title="{group_title}",{channel_name}\n{stream_url}\n'
                else:
                    content += f'{channel_name},{stream_url}\n'

                index += 1
        except Exception:
            continue
            
    return content

# ==========================================
# Web 接口
# ==========================================
@app.route('/')
def index():
    return jsonify({
        "status": "running",
        "last_run_time": LAST_RUN_TIME,
        "endpoints": ["/ids", "/m3u", "/m3u_plus", "/txt", "/txt_plus"]
    })

@app.route('/m3u')
def get_m3u_clean():
    return Response(generate_playlist("m3u", "clean"), mimetype='text/plain; charset=utf-8', headers={"Access-Control-Allow-Origin": "*"})

@app.route('/m3u_plus')
def get_m3u_plus():
    return Response(generate_playlist("m3u", "plus"), mimetype='text/plain; charset=utf-8', headers={"Access-Control-Allow-Origin": "*"})

@app.route('/txt')
def get_txt_clean():
    return Response(generate_playlist("txt", "clean"), mimetype='text/plain; charset=utf-8', headers={"Access-Control-Allow-Origin": "*"})

@app.route('/txt_plus')
def get_txt_plus():
    return Response(generate_playlist("txt", "plus"), mimetype='text/plain; charset=utf-8', headers={"Access-Control-Allow-Origin": "*"})

if __name__ == "__main__":
    scheduler = BackgroundScheduler(timezone="Asia/Shanghai")
    scheduler.add_job(scrape_job, 'interval', minutes=12, next_run_time=datetime.now())
    scheduler.start()
    app.run(host='0.0.0.0', port=5000, use_reloader=False)
