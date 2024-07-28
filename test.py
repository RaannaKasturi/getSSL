import scrapy

class ProxySpider(scrapy.Spider):
    name = 'proxy_spider'
    start_urls = ['https://free-proxy-list.net/']

    def parse(self, response):
        for row in response.css('table#proxylisttable tbody tr'):
            ip = row.css('td:nth-child(1)::text').get()
            port = row.css('td:nth-child(2)::text').get()
            yield f"{ip}:{port}"

# Run the spider
from scrapy.utils.project import get_project_settings
from scrapy.crawler import CrawlerProcess

process = CrawlerProcess(get_project_settings())
process.crawl(ProxySpider)
process.start()