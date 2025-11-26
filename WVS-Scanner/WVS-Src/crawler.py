# crawler.py

import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore
import time

SAFE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf", ".css", ".js", ".ico", ".woff", ".woff2", ".ttf")

class Crawler:
    def __init__(self, base_url, max_pages=200, delay=0.2, user_agent=None):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.links = set()
        self.max_pages = max_pages
        self.delay = delay
        self.headers = {"User-Agent": user_agent or "PassiveCrawler/1.0 (+https://example.com)"}

    def crawl(self, start_url=None):
        start_url = start_url or self.base_url
        queue = [start_url]
        while queue and len(self.links) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            try:
                r = requests.get(url, headers=self.headers, timeout=6, allow_redirects=True)
            except Exception as e:
                print(Fore.YELLOW + f"[!] crawl: failed to fetch {url}: {e}")
                continue

            # store the URL (normalize)
            self.links.add(r.url)

            # parse links
            try:
                soup = BeautifulSoup(r.text, "html.parser")
            except Exception:
                continue

            for a in soup.find_all("a", href=True):
                link = urljoin(r.url, a["href"].split("#")[0])
                parsed = urlparse(link)

                # keep only same-domain links
                if parsed.netloc and parsed.netloc != self.domain:
                    continue

                # skip static/binary files
                if any(parsed.path.lower().endswith(ext) for ext in SAFE_EXT):
                    continue

                # normalize trailing slash
                link = link.rstrip("/")

                if link not in self.visited and link not in queue and len(self.links) + len(queue) < self.max_pages:
                    queue.append(link)

            time.sleep(self.delay)

    def get_links(self):
        return sorted(self.links)
