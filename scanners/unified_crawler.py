#!/usr/bin/env python3

import re
import time
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from urllib.robotparser import RobotFileParser
from typing import List, Set, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from dataclasses import dataclass
from bs4 import BeautifulSoup


@dataclass
class CrawlResult:
    """Data class for crawl results"""
    url: str
    parameters: Dict[str, List[str]]
    forms: List[Dict]
    response_code: int
    content_type: str
    has_parameters: bool


class UnifiedCrawler:
    """
    Modern unified web crawler for security testing
    
    Features:
    - Finds URLs with GET parameters (for all injection types)
    - Discovers forms with POST parameters (for XSS, CRLF, Command Injection)
    - Respects robots.txt (optional)
    - Multi-threaded crawling
    - Smart duplicate detection
    - Configurable depth and scope
    """
    
    def __init__(self, 
                 max_depth: int = 2,
                 max_urls: int = 50,
                 max_threads: int = 5,
                 timeout: int = 10,
                 respect_robots: bool = False):
        
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.max_threads = max_threads
        self.timeout = timeout
        self.respect_robots = respect_robots
        
        # State tracking
        self.visited_urls: Set[str] = set()
        self.found_urls: Dict[str, CrawlResult] = {}
        self.domain_filter: Optional[str] = None
        self.robots_parser: Optional[RobotFileParser] = None
        
        # Thread safety
        self.lock = threading.Lock()
        
        # HTTP session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def crawl_website(self, start_url: str, progress_callback=None) -> List[str]:
        """
        Crawl website starting from start_url
        Returns list of URLs with parameters suitable for injection testing
        """
        self.visited_urls.clear()
        self.found_urls.clear()
        
        # Parse start URL and set domain filter
        parsed_start = urlparse(start_url)
        self.domain_filter = f"{parsed_start.scheme}://{parsed_start.netloc}"
        
        # Setup robots.txt parser if enabled
        if self.respect_robots:
            self._setup_robots_parser(self.domain_filter)
        
        print(f"Starting crawl of {start_url}")
        print(f"Domain filter: {self.domain_filter}")
        print(f"Max depth: {self.max_depth}, Max URLs: {self.max_urls}")
        
        # Start crawling
        urls_to_crawl = [(start_url, 0)]  # (url, depth)
        
        while urls_to_crawl and len(self.found_urls) < self.max_urls:
            # Process batch of URLs
            current_batch = urls_to_crawl[:self.max_threads]
            urls_to_crawl = urls_to_crawl[self.max_threads:]
            
            # Crawl batch concurrently
            new_urls = self._crawl_batch(current_batch)
            
            # Add new URLs to crawl queue (if within depth limit)
            for url, depth in new_urls:
                if depth < self.max_depth and len(self.found_urls) < self.max_urls:
                    urls_to_crawl.append((url, depth))
            
            # Update progress
            if progress_callback:
                progress_callback(len(self.found_urls), self.max_urls)
        
        # Extract all URLs and URLs with parameters
        all_urls = [result.url for result in self.found_urls.values()]
        parameter_urls = [
            result.url for result in self.found_urls.values()
            if result.has_parameters
        ]
        
        print(f"Crawl completed. Found {len(parameter_urls)} URLs with parameters out of {len(all_urls)} total URLs.")
        
        # Return all URLs so the caller can decide what to do with them
        return all_urls
    
    def _crawl_batch(self, urls_depth_pairs: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
        """Crawl a batch of URLs concurrently"""
        new_urls = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit crawl tasks
            future_to_url = {
                executor.submit(self._crawl_single_url, url, depth): (url, depth)
                for url, depth in urls_depth_pairs
            }
            
            # Process completed crawls
            for future in as_completed(future_to_url):
                url, depth = future_to_url[future]
                try:
                    discovered_urls = future.result()
                    # Add discovered URLs with incremented depth
                    new_urls.extend([(discovered_url, depth + 1) for discovered_url in discovered_urls])
                except Exception as e:
                    print(f"Error crawling {url}: {e}")
        
        return new_urls
    
    def _crawl_single_url(self, url: str, depth: int) -> List[str]:
        """Crawl a single URL and return discovered URLs"""
        
        with self.lock:
            if url in self.visited_urls or len(self.found_urls) >= self.max_urls:
                return []
            self.visited_urls.add(url)
        
        print(f"Crawling (depth {depth}): {url}")
        
        try:
            # Check robots.txt
            if self.respect_robots and self.robots_parser:
                if not self.robots_parser.can_fetch('*', url):
                    print(f"Blocked by robots.txt: {url}")
                    return []
            
            # Make request
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Parse response
            crawl_result = self._parse_response(url, response)
            
            with self.lock:
                self.found_urls[url] = crawl_result
            
            # Extract new URLs to crawl
            if response.status_code == 200 and 'text/html' in response.headers.get('content-type', ''):
                return self._extract_urls_from_html(url, response.text)
            
        except requests.exceptions.RequestException as e:
            print(f"Request failed for {url}: {e}")
        except Exception as e:
            print(f"Unexpected error crawling {url}: {e}")
        
        return []
    
    def _parse_response(self, url: str, response: requests.Response) -> CrawlResult:
        """Parse HTTP response and extract relevant information"""
        
        # Parse URL parameters
        parsed_url = urlparse(url)
        parameters = parse_qs(parsed_url.query)
        
        # Parse forms (if HTML content)
        forms = []
        if 'text/html' in response.headers.get('content-type', ''):
            forms = self._extract_forms(response.text)
        
        # Determine if URL has parameters (query params or forms)
        has_parameters = bool(parameters or forms)
        
        return CrawlResult(
            url=url,
            parameters=parameters,
            forms=forms,
            response_code=response.status_code,
            content_type=response.headers.get('content-type', ''),
            has_parameters=has_parameters
        )
    
    def _extract_urls_from_html(self, base_url: str, html_content: str) -> List[str]:
        """Extract URLs from HTML content"""
        discovered_urls = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract URLs from various tags
            url_sources = [
                ('a', 'href'),
                ('form', 'action'),
                ('iframe', 'src'),
                ('script', 'src'),
                ('link', 'href')
            ]
            
            for tag_name, attr_name in url_sources:
                for tag in soup.find_all(tag_name):
                    url = tag.get(attr_name)
                    if url:
                        # Convert relative URLs to absolute
                        absolute_url = urljoin(base_url, url)
                        
                        # Filter URLs
                        if self._should_crawl_url(absolute_url):
                            discovered_urls.append(absolute_url)
            
        except Exception as e:
            print(f"Error parsing HTML from {base_url}: {e}")
        
        return discovered_urls
    
    def _extract_forms(self, html_content: str) -> List[Dict]:
        """Extract form information from HTML"""
        forms = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                # Extract input fields
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    
                    if input_data['name']:  # Only include named inputs
                        form_data['inputs'].append(input_data)
                
                if form_data['inputs']:  # Only include forms with inputs
                    forms.append(form_data)
        
        except Exception as e:
            print(f"Error extracting forms: {e}")
        
        return forms
    
    def _should_crawl_url(self, url: str) -> bool:
        """Determine if URL should be crawled"""
        
        # Skip if already visited
        if url in self.visited_urls:
            return False
        
        # Parse URL
        parsed = urlparse(url)
        
        # Must be same domain (if domain filter is set)
        if self.domain_filter:
            url_domain = f"{parsed.scheme}://{parsed.netloc}"
            if url_domain != self.domain_filter:
                return False
        
        # Skip non-HTTP(S) URLs
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Skip certain file extensions
        skip_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', 
                          '.zip', '.rar', '.tar', '.gz', '.exe', '.dmg']
        
        path_lower = parsed.path.lower()
        if any(path_lower.endswith(ext) for ext in skip_extensions):
            return False
        
        # Skip logout/admin URLs (to avoid unintended actions)
        avoid_patterns = ['logout', 'admin', 'delete', 'remove', 'signout']
        if any(pattern in url.lower() for pattern in avoid_patterns):
            return False
        
        return True
    
    def _setup_robots_parser(self, domain: str):
        """Setup robots.txt parser"""
        try:
            robots_url = urljoin(domain, '/robots.txt')
            self.robots_parser = RobotFileParser()
            self.robots_parser.set_url(robots_url)
            self.robots_parser.read()
        except Exception as e:
            print(f"Could not parse robots.txt for {domain}: {e}")
            self.robots_parser = None
    
    def get_crawl_statistics(self) -> Dict:
        """Get crawling statistics"""
        total_urls = len(self.found_urls)
        parameter_urls = len([r for r in self.found_urls.values() if r.has_parameters])
        
        return {
            'total_urls_found': total_urls,
            'urls_with_parameters': parameter_urls,
            'urls_with_forms': len([r for r in self.found_urls.values() if r.forms]),
            'response_codes': {
                str(code): len([r for r in self.found_urls.values() if r.response_code == code])
                for code in set(r.response_code for r in self.found_urls.values())
            }
        }

# Example usage and testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Unified Web Crawler for Security Testing")
    parser.add_argument("url", help="Starting URL to crawl")
    parser.add_argument("--depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("--max-urls", type=int, default=50, help="Maximum URLs to crawl")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads")
    
    args = parser.parse_args()
    
    def progress_callback(current, total):
        print(f"Progress: {current}/{total} URLs processed")
    
    crawler = UnifiedCrawler(
        max_depth=args.depth,
        max_urls=args.max_urls,
        max_threads=args.threads
    )
    
    print(f"Starting crawl of {args.url}")
    start_time = time.time()
    
    urls_with_params = crawler.crawl_website(args.url, progress_callback)
    
    end_time = time.time()
    
    print(f"\nCrawl completed in {end_time - start_time:.2f} seconds")
    print(f"Found {len(urls_with_params)} URLs with parameters:")
    
    for url in urls_with_params:
        print(f"  {url}")
    
    print(f"\nCrawl Statistics:")
    stats = crawler.get_crawl_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
