import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_links = set()
        self.links_to_scan = set()

    def crawl(self, url=None):
        url = url or self.base_url
        if url in self.visited_links:
            return

        self.visited_links.add(url)
        try:
            res = requests.get(url)
            soup = BeautifulSoup(res.text, 'html.parser')
            for link in soup.find_all("a", href=True):
                href = link['href']
                full_url = urljoin(url, href)
                if self.is_valid(full_url):
                    self.links_to_scan.add(full_url)
                    self.crawl(full_url)
        except Exception:
            pass

    def is_valid(self, url):
        parsed = urlparse(url)
        return parsed.scheme in ['http', 'https'] and self.base_url in url

    def get_links(self):
        return list(self.links_to_scan)

