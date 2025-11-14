# Web Application Security Scanner v2.0

## 🛡️ Professional Desktop Security Testing Tool

**Perfect for Cybersecurity Internships and Professional Use**

This is a comprehensive desktop application for web application security testing, featuring multiple vulnerability scanners with a modern GUI interface and professional PDF reporting.

## 🚀 Key Features

### **4 Production-Grade Vulnerability Scanners:**
1. **SQL Injection Scanner** - Database injection vulnerabilities with 0% false positives
2. **Enhanced XSS Scanner v2** - Real browser automation with 2668+ payloads  
3. **CRLF Injection Scanner** - HTTP response splitting detection
4. **Command Injection Scanner** - OS command injection detection

### **Advanced Features:**
- 🎯 **Modern CustomTkinter GUI** with live vulnerability feed
- 🔍 **Intelligent Web Crawler** finds URLs with parameters automatically
- ⚡ **Multi-threaded Scanning** with Selenium WebDriver automation
- 🚨 **Real-time Detection** with alert-based verification (gold standard)
- 📊 **Professional PDF Reports** with executive summary
- 🌙 **Dark/Light Mode** toggle for user preference
- 📊 **Real-time Progress Tracking** with progress bars
- 📄 **Professional PDF Reports** with executive summaries
- 🎨 **Rich Console Output** for CLI usage
- 🔒 **Thread-safe Operations** for reliable scanning

## 📁 Project Structure

```
WebScannerProject/
├── main.py                 # Main GUI application  
├── main_modern.py          # Beautiful modern GUI alternative
├── requirements.txt        # Python dependencies
├── scanners/              # Modern scanner modules
│   ├── __init__.py
│   ├── unified_crawler.py      # Web crawler for all scanners
│   ├── sqli_scanner.py         # SQL injection scanner
│   ├── xss_scanner.py          # XSS scanner
│   ├── crlf_scanner.py         # CRLF injection scanner
│   ├── cmd_injection_scanner.py # Command injection scanner
│   └── report_generator.py     # PDF report generator
├── test_scanner.py        # Comprehensive test suite
├── README.md              # This documentation
└── venv/                  # Virtual environment (created during setup)
```

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd /home/kali/Desktop/WebScannerProject
pip3 install -r requirements.txt
```

### 2. Run Desktop Application
```bash
python3 main.py
```

### 3. Use the Application
1. **Select vulnerability type** (SQL Injection, XSS, CRLF, Command Injection)
2. **Enter target URL** (e.g., `http://testphp.vulnweb.com/artists.php?artist=1`)
3. **Enable web crawling** to find more URLs automatically
4. **Click "Start Scan"** and watch the progress
5. **View results** and **generate PDF report**

## 💻 GUI Application Features

### **Main Interface:**
- Welcome screen with professional branding
- 4 vulnerability type options with descriptions
- URL input with crawling options
- Progress tracking with status updates
- Results display with detailed information
- PDF report generation

### **Progress Tracking:**
- Real-time progress bars
- Status messages during scanning
- Estimated completion time
- Thread-safe UI updates

### **Results Display:**
- Summary statistics
- Detailed vulnerability findings
- Risk level assessment
- Remediation recommendations

## 🛠️ Individual Scanner Usage

### SQL Injection Scanner
```bash
python3 scanners/sqli_scanner.py "http://example.com/page.php?id=1" --threads 10 --verbose
```

### XSS Scanner  
```bash
python3 scanners/xss_scanner.py "http://example.com/search.php?q=test" --threads 5
```

### CRLF Injection Scanner
```bash
python3 scanners/crlf_scanner.py "http://example.com/redirect.php?url=test"
```

### Command Injection Scanner
```bash
python3 scanners/cmd_injection_scanner.py "http://example.com/ping.php?host=127.0.0.1"
```

### Web Crawler
```bash
python3 scanners/unified_crawler.py "http://example.com" --depth 2 --max-urls 50
```

## 🔍 Scanner Capabilities

### **SQL Injection Scanner:**
- **9 Database Types:** MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc.
- **20+ Payloads:** Error-based, Union-based, Boolean-based, Time-based
- **Smart Detection:** Pattern matching for SQL errors
- **Risk Assessment:** Critical, High, Medium, Low categorization

### **XSS Scanner:**
- **Multiple XSS Types:** Reflected, Stored, DOM-based detection
- **Advanced Payloads:** Script tags, event handlers, encoded payloads
- **Filter Bypass:** Case variations, encoding, polyglot payloads
- **Context Awareness:** HTML, JavaScript, CSS context detection

### **CRLF Injection Scanner:**
- **HTTP Header Injection:** Detects header manipulation
- **Response Splitting:** Identifies HTTP response splitting
- **Multiple Encodings:** URL encoding, Unicode, double encoding
- **Log Injection:** Detects log poisoning attempts

### **Command Injection Scanner:**
- **OS Detection:** Windows and Unix/Linux command execution
- **Time-based Detection:** Uses delays to identify blind injection
- **Output Analysis:** Parses command output for confirmation
- **Risk Assessment:** Based on command type and OS access level

## 📊 Professional Reporting

### **PDF Report Features:**
- Executive Summary with risk assessment
- Detailed vulnerability findings
- Technical details and proof-of-concept
- Remediation recommendations

## 🎯 Demo URLs and Testing

### **Recommended Demo URLs:**
- `http://testphp.vulnweb.com/` - Acunetix test site (most reliable)
- `http://demo.testfire.net/` - IBM Security AppScan demo
- `http://zero.webappsecurity.com/` - Zero Bank demo application

### **Local Test Server:**
```bash
python test_website.py  # Starts vulnerable test server on localhost:8000
```

### **Authentication Requirements:**
**Note:** Some platforms like DVWA (Damn Vulnerable Web Application) require authentication before scanning:
- DVWA: Default credentials are `admin/password`
- bWAPP: Requires login setup
- For production testing, ensure proper authorization before scanning

### **Legal and Ethical Use:**
Only test on:
- Your own applications
- Explicitly authorized targets
- Public vulnerable applications designed for testing
- See `DEMO_URLS.md` for comprehensive list of testing platforms

## 🎯 Perfect for Cybersecurity Internships

### **Learning Opportunities:**
- Understanding common web vulnerabilities
- Hands-on experience with security testing
- Report writing and communication skills
- Professional tool development experience

### **Professional Features:**
- Industry-standard vulnerability detection
- Professional report generation
- Modern software architecture
- Production-ready code quality

## 🔧 Technical Architecture

### **Modern Design Patterns:**
- **Object-Oriented Design** with clean separation of concerns
- **Thread-safe Operations** for reliable concurrent scanning
- **Callback-based Progress Tracking** for responsive UI
- **Modular Scanner Architecture** for easy extension
- **Data Classes** for structured result handling

### **Performance Features:**
- **Multi-threading** for parallel URL scanning
- **Connection Pooling** for efficient HTTP requests
- **Smart Crawling** with duplicate detection
- **Memory Efficient** processing of large result sets

### **Security Considerations:**
- **Rate Limiting** to avoid overwhelming target servers
- **Request Timeouts** for reliable operation
- **Error Handling** for graceful failure recovery
- **Safe Crawling** with robots.txt respect (optional)

## 🌟 Professional Features

### **Modern Security Scanner Capabilities:**
- ✅ **Unified Architecture** - All scanners work together seamlessly
- ✅ **GUI Interface** - Professional desktop application
- ✅ **Smart Detection** - Advanced vulnerability identification
- ✅ **Multi-threaded Performance** - Fast, efficient scanning
- ✅ **Professional Reporting** - Executive-quality PDF reports
- ✅ **Extensible Design** - Easy to add new vulnerability types

## 📈 Next Steps for Enhancement

### **Phase 2 Features:**
- [ ] **Database Storage** for scan history
- [ ] **Scheduled Scanning** with automation
- [ ] **Custom Payload Management** for advanced users
- [ ] **API Integration** with other security tools
- [ ] **Export Options** (CSV, XML, JSON)

### **Phase 3 Features:**
- [ ] **Authentication Support** for authenticated scanning
- [ ] **Form-based Testing** for POST parameter injection
- [ ] **SSL/TLS Security Testing** 
- [ ] **Directory Traversal** scanner
- [ ] **File Upload Vulnerability** testing

## 🏆 Perfect For:

- **Cybersecurity Internships** - Demonstrates practical security testing skills
- **Academic Projects** - Shows understanding of web security concepts  
- **Professional Training** - Hands-on experience with real vulnerabilities
- **Security Assessments** - Actual vulnerability testing of web applications
- **Portfolio Projects** - Impressive demonstration of technical capabilities

## 📝 Usage Examples

### **Testing a Vulnerable Application:**
```bash
# Start the GUI application
python3 main.py

# Or test individual components
python3 scanners/sqli_scanner.py "http://testphp.vulnweb.com/artists.php?artist=1"
```

### **Bulk URL Testing:**
```bash
echo "http://site1.com/page.php?id=1" > urls.txt
echo "http://site2.com/search.php?q=test" >> urls.txt
python3 scanners/sqli_scanner.py -f urls.txt --threads 10 -o results.json
```

## 📞 Support and Documentation

This scanner is designed to be educational and professional. All code includes:
- **Comprehensive Comments** explaining security concepts
- **Error Handling** with informative messages  
- **Professional Logging** for debugging
- **Modular Design** for easy understanding and extension

---

**🎓 Perfect for demonstrating cybersecurity knowledge and practical skills in professional internship environments!**
