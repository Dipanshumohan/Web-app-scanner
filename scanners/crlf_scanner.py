#!/usr/bin/env python3

import re
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional, Tuple, Callable, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dataclasses import dataclass
import threading
import random
import string


@dataclass
class CRLFResult:
    """Data class for CRLF injection scan results"""
    url: str
    is_vulnerable: bool
    vulnerability_type: str
    injection_type: str  # 'header_injection', 'response_splitting', 'log_injection'
    payload: Optional[str]
    response_time: float
    error_message: Optional[str]
    risk_level: str
    timestamp: datetime
    additional_info: Dict[str, Any]


class CRLFScanner:
    """
    CRLF Injection Scanner - Production Grade
    
    Features:
    - Context-aware CRLF detection
    - Real HTTP response validation
    - Minimal false positives
    - Multiple encoding techniques
    - Evidence-based detection
    """
    
    def __init__(self, max_threads: int = 5, timeout: int = 10, delay: float = 0.1):
        self.max_threads = max_threads
        self.timeout = timeout
        self.delay = delay
        
        self.lock = threading.Lock()
        self.stop_scanning = False
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.test_marker = self._generate_unique_marker()
        
        # CRLF injection payloads with unique markers
        self.payloads = self._generate_crlf_payloads()
        
    def _generate_unique_marker(self) -> str:
        """Generate a unique marker for this scan session"""
        timestamp = str(int(time.time()))
        random_part = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return f"CRLF{timestamp}{random_part}"
    
    def _generate_crlf_payloads(self) -> List[Dict[str, str]]:
        """Generate CRLF payloads with unique markers for accurate detection"""
        marker = self.test_marker
        
        return [
            {
                'payload': f'\\r\\nX-{marker}: HeaderInjection',
                'type': 'header_injection',
                'encoding': 'raw',
                'description': 'Raw CRLF header injection'
            },
            {
                'payload': f'%0d%0aX-{marker}: HeaderInjection',
                'type': 'header_injection', 
                'encoding': 'url',
                'description': 'URL-encoded CRLF header injection'
            },
            {
                'payload': f'%0D%0AX-{marker}: HeaderInjection',
                'type': 'header_injection',
                'encoding': 'url_upper',
                'description': 'URL-encoded CRLF (uppercase)'
            },
            
            {
                'payload': f'\\r\\n\\r\\n<html><body>{marker}</body></html>',
                'type': 'response_splitting',
                'encoding': 'raw',
                'description': 'HTTP response splitting with HTML'
            },
            {
                'payload': f'%0d%0a%0d%0a<script>/*{marker}*/</script>',
                'type': 'response_splitting',
                'encoding': 'url',
                'description': 'Response splitting with script injection'
            },
            
            {
                'payload': f'\\r\\nSet-Cookie: {marker}=injected',
                'type': 'header_injection',
                'encoding': 'raw',
                'description': 'CRLF cookie injection'
            },
            {
                'payload': f'%0d%0aSet-Cookie: {marker}=injected',
                'type': 'header_injection',
                'encoding': 'url',
                'description': 'URL-encoded cookie injection'
            },
            
            {
                'payload': f'\\r\\nLocation: http://evil.com/{marker}',
                'type': 'header_injection',
                'encoding': 'raw',
                'description': 'Location header injection'
            },
            
            {
                'payload': f'%250d%250aX-{marker}: DoubleEncoded',
                'type': 'header_injection',
                'encoding': 'double_url',
                'description': 'Double URL-encoded CRLF'
            },
            
            {
                'payload': f'\\u000d\\u000aX-{marker}: Unicode',
                'type': 'header_injection',
                'encoding': 'unicode',
                'description': 'Unicode-encoded CRLF'
            }
        ]
    
    def _clean_payload_for_request(self, payload: str) -> str:
        """Convert payload string to actual bytes for HTTP request"""
        cleaned = payload.replace('\\r\\n', '\\r\\n')
        cleaned = cleaned.replace('\\r', '\\r')
        cleaned = cleaned.replace('\\n', '\\n')
        cleaned = cleaned.replace('\\u000d\\u000a', '\\r\\n')
        cleaned = cleaned.replace('\\u000D\\u000A', '\\r\\n')
        return cleaned
    
    def _test_crlf_payload(self, url: str, payload_info: Dict[str, str]) -> CRLFResult:
        """Test a single CRLF payload with context-aware detection"""
        start_time = time.time()
        payload = payload_info['payload']
        injection_type = payload_info['type']
        encoding = payload_info['encoding']
        
        try:
            parsed_url = urlparse(url)
            if not parsed_url.query:
                return CRLFResult(
                    url=url,
                    is_vulnerable=False,
                    vulnerability_type="CRLF",
                    injection_type="",
                    payload=payload,
                    response_time=0.0,
                    error_message="No query parameters found",
                    risk_level="Info",
                    timestamp=datetime.now(),
                    additional_info={'encoding': encoding}
                )
            
            # Inject payload into each parameter
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            
            for param_name in query_params.keys():
                if self.stop_scanning:
                    break
                
                modified_params = query_params.copy()
                clean_payload = self._clean_payload_for_request(payload)
                modified_params[param_name] = [clean_payload]
                
                new_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))
                
                response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                response_time = time.time() - start_time
                
                is_vulnerable, evidence = self._analyze_crlf_response(
                    response, payload_info, self.test_marker
                )
                
                if is_vulnerable:
                    risk_level = self._determine_risk_level(injection_type, evidence)
                    
                    return CRLFResult(
                        url=test_url,
                        is_vulnerable=True,
                        vulnerability_type="CRLF",
                        injection_type=injection_type,
                        payload=payload,
                        response_time=response_time,
                        error_message="",
                        risk_level=risk_level,
                        timestamp=datetime.now(),
                        additional_info={
                            'evidence': evidence,
                            'parameter': param_name,
                            'encoding': encoding,
                            'marker': self.test_marker,
                            'confidence': 'high'
                        }
                    )
                
                time.sleep(self.delay)
        
        except Exception as e:
            response_time = time.time() - start_time
            return CRLFResult(
                url=url,
                is_vulnerable=False,
                vulnerability_type="CRLF",
                injection_type="",
                payload=payload,
                response_time=response_time,
                error_message=str(e),
                risk_level="Error",
                timestamp=datetime.now(),
                additional_info={'encoding': encoding}
            )
        
        response_time = time.time() - start_time
        return CRLFResult(
            url=url,
            is_vulnerable=False,
            vulnerability_type="CRLF",
            injection_type="",
            payload=payload,
            response_time=response_time,
            error_message="",
            risk_level="",
            timestamp=datetime.now(),
            additional_info={'encoding': encoding}
        )
    
    def _analyze_crlf_response(self, response: requests.Response, 
                              payload_info: Dict[str, str], marker: str) -> Tuple[bool, str]:
        """
        Analyze HTTP response for CRLF injection evidence with high accuracy
        Returns (is_vulnerable, evidence)
        """
        payload_type = payload_info['type']
        
        for header_name, header_value in response.headers.items():
            if marker in header_name or marker in str(header_value):
                return True, f"Injected header detected: {header_name}: {header_value}"
        
        if payload_type == 'response_splitting':
            if marker in response.text:
                if self._is_actual_response_splitting(response, marker, payload_info):
                    return True, f"Response splitting detected with marker: {marker}"
        
        if payload_type == 'header_injection':
            if self._detect_header_injection_evidence(response, marker):
                return True, f"Header injection evidence found with marker: {marker}"
        
        cookies = response.headers.get('Set-Cookie', '')
        if marker in cookies:
            return True, f"Cookie injection detected: {cookies}"
        
        location = response.headers.get('Location', '')
        if marker in location:
            return True, f"Location header injection detected: {location}"
        
        return False, ""
    
    def _is_actual_response_splitting(self, response: requests.Response, marker: str, payload_info: Dict[str, str]) -> bool:
        """Check if marker in response body indicates actual response splitting"""
        text = response.text
        payload = payload_info['payload']
        
        if self._is_echo_only(text, marker, payload):
            return False
        
        # For URL-encoded payloads with script injection, check very specifically
        if 'script' in payload.lower() and '%0d%0a' in payload:
            expected_script = f'<script>/*{marker}*/</script>'
            if expected_script in text:
                return True
            
            comment_only = f'/*{marker}*/'
            if comment_only in text and expected_script not in text:
                return False
        
        if '<html><body>' in payload:
            expected_html = f'<html><body>{marker}</body></html>'
            if expected_html in text:
                return True
        
        if f'<script>' in text and marker in text:
            script_pattern = f'<script[^>]*>[^<]*{re.escape(marker)}[^<]*</script>'
            if re.search(script_pattern, text, re.IGNORECASE):
                # Verify this is not just echoing our payload
                if f'/*{marker}*/' in text:
                    # This is likely just reflection of our comment payload
                    return False
                return True
        
        if text.strip().startswith('HTTP/1.1') and marker in text:
            return True
        
        if text.startswith('<html>') and f'<body>{marker}</body>' in text:
            return True
        
        return False
    
    def _detect_header_injection_evidence(self, response: requests.Response, marker: str) -> bool:
        """Detect evidence of successful header injection"""
        suspicious_headers = ['x-injected', 'x-test', 'x-crlf']
        
        for header_name in response.headers.keys():
            header_lower = header_name.lower()
            if any(suspicious in header_lower for suspicious in suspicious_headers):
                if marker.lower() in header_lower:
                    return True
        
        return False
    
    def _determine_risk_level(self, injection_type: str, evidence: str) -> str:
        """Determine risk level based on injection type and evidence"""
        if injection_type == 'response_splitting':
            return 'Critical'
        elif injection_type == 'header_injection':
            if 'location' in evidence.lower() or 'set-cookie' in evidence.lower():
                return 'High'
            else:
                return 'Medium'
        else:
            return 'Medium'
    
    def scan_single_url(self, url: str, progress_callback: Optional[Callable] = None,
                       status_callback: Optional[Callable] = None) -> List[CRLFResult]:
        """Scan a single URL for CRLF injection vulnerabilities"""
        results = []
        
        if status_callback:
            status_callback(f"🔍 Scanning CRLF: {url}")
        
        # Test each payload
        for i, payload_info in enumerate(self.payloads):
            if self.stop_scanning:
                break
            
            if progress_callback:
                progress_callback(i + 1, len(self.payloads))
            
            if status_callback:
                payload_desc = payload_info.get('description', 'CRLF payload')
                status_callback(f"🧪 Testing {payload_desc}")
            
            result = self._test_crlf_payload(url, payload_info)
            results.append(result)
            
            # If we found a high-confidence vulnerability, we can stop testing more payloads
            if result.is_vulnerable and result.additional_info.get('confidence') == 'high':
                if status_callback:
                    status_callback(f"🎯 CRLF vulnerability confirmed in {url}")
                break
        
        return results
    
    def scan_urls(self, urls: List[str], progress_callback: Optional[Callable] = None,
                 status_callback: Optional[Callable] = None) -> List[CRLFResult]:
        """Scan multiple URLs for CRLF injection vulnerabilities"""
        all_results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {
                executor.submit(self.scan_single_url, url, None, status_callback): url 
                for url in urls
            }
            
            for i, future in enumerate(as_completed(future_to_url)):
                if self.stop_scanning:
                    break
                
                if progress_callback:
                    progress_callback(i + 1, len(urls))
                
                try:
                    results = future.result(timeout=30)
                    all_results.extend(results)
                except Exception as e:
                    url = future_to_url[future]
                    error_result = CRLFResult(
                        url=url,
                        is_vulnerable=False,
                        vulnerability_type="CRLF",
                        injection_type="",
                        payload="",
                        response_time=0.0,
                        error_message=str(e),
                        risk_level="Error",
                        timestamp=datetime.now(),
                        additional_info={}
                    )
                    all_results.append(error_result)
        
        return all_results
    
    def stop(self):
        """Stop the current scanning operation"""
        self.stop_scanning = True


def scan_crlf(url: str, progress_callback: Optional[Callable] = None, 
              status_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
    """
    Compatibility function for main scanner integration
    
    Args:
        url: URL to scan
        progress_callback: Optional progress callback function
        status_callback: Optional status callback function
        
    Returns:
        List of vulnerability dictionaries
    """
    scanner = CRLFScanner()
    
    try:
        results = scanner.scan_single_url(url, progress_callback, status_callback)
        
        vulnerabilities = []
        for result in results:
            if result.is_vulnerable:
                vulnerabilities.append({
                    'url': result.url,
                    'vulnerability_type': result.vulnerability_type,
                    'risk_level': result.risk_level,
                    'payload': result.payload,
                    'details': {
                        'injection_type': result.injection_type,
                        'evidence': result.additional_info.get('evidence', ''),
                        'parameter': result.additional_info.get('parameter', ''),
                        'encoding': result.additional_info.get('encoding', ''),
                        'confidence': result.additional_info.get('confidence', ''),
                        'response_time': result.response_time,
                        'timestamp': result.timestamp.isoformat()
                    }
                })
        
        return vulnerabilities
    
    finally:
        scanner.stop()


if __name__ == "__main__":
    test_url = "http://localhost:8000/search?q=test"
    print("🧪 Testing CRLF Scanner...")
    
    results = scan_crlf(test_url)
    print(f"📊 Results: {len(results)} vulnerabilities found")
    
    for vuln in results:
        print(f"🚨 {vuln['vulnerability_type']}: {vuln['url']}")
        print(f"   Risk Level: {vuln['risk_level']}")
        print(f"   Injection Type: {vuln['details']['injection_type']}")
        print(f"   Evidence: {vuln['details']['evidence']}")
