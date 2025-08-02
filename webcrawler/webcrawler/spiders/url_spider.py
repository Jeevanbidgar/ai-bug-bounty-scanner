import scrapy
from urllib.parse import urlparse

class URLSpider(scrapy.Spider):
    name = "url_spider"
    allowed_domains = []
    start_urls = []

    def __init__(self, target_url=None, *args, **kwargs):
        super(URLSpider, self).__init__(*args, **kwargs)
        self.start_urls = [target_url]
        self.allowed_domains = [urlparse(target_url).netloc]

    def parse(self, response):
        self.logger.info(f"Crawling: {response.url}")
        yield {'url': response.url}

        for href in response.css('a::attr(href)').getall():
            full_url = response.urljoin(href)
            if urlparse(full_url).netloc == self.allowed_domains[0]:
                yield scrapy.Request(full_url, callback=self.parse)
