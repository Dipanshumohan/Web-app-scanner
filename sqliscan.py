import requests  # Library to make HTTP requests (GET, POST, etc.)
from bs4 import BeautifulSoup  # Parses HTML content to extract information like forms
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse  # For URL manipulation
import json  # To save results in JSON format for easy reading & sharing

# Create a requests Session for persistent connection & to set headers like User-Agent
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"


# Load SQL injection payloads (test strings) from a file
def load_payloads(filename="payloads.txt"):
    with open(filename, "r") as f:
        # Read all lines, strip whitespace, and ignore empty lines
        return [line.strip() for line in f if line.strip()]


# Extract all forms from a webpage at 'url'
def get_forms(url):
    # Send GET request and parse HTML
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    # Return list of all <form> elements
    return soup.find_all("form")


# Extract form details: action URL, method, and all input fields with their info
def form_details(form):
    action = form.attrs.get("action")  # Where form submits data
    method = form.attrs.get("method", "get").lower()  # HTTP method (default GET)
    inputs = []
    # Extract inputs, textareas, and selects
    for tag in form.find_all(["input", "textarea", "select"]):
        input_type = tag.attrs.get("type", "text")
        input_name = tag.attrs.get("name")
        input_value = tag.attrs.get("value", "")
        if tag.name == "textarea":
            input_value = tag.text  # Text inside textarea
        if input_name:
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
    return {"action": action, "method": method, "inputs": inputs}


# Check if the HTTP response contains signs of SQL error messages
def is_vulnerable(response):
    errors = {
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "syntax error"
    }
    # Return True if any known error message is found in response text (case-insensitive)
    return any(error in response.text.lower() for error in errors)


# Scan a single form by injecting payloads in inputs
def scan_form(url, form, payloads):
    details = form_details(form)  # Get form info
    # Resolve the action URL relative to the base url if needed
    target = urljoin(url, details["action"]) if details["action"] else url
    results = []

    for payload in payloads:
        data = {}
        # Prepare form data with payload injected in each input field
        for input_tag in details["inputs"]:
            # If hidden field or already has a value, append payload
            if input_tag["type"] == "hidden" or input_tag["value"]:
                data[input_tag["name"]] = input_tag["value"] + payload
            # Otherwise send 'test' + payload as input value (skip submit buttons)
            elif input_tag["type"] != "submit":
                data[input_tag["name"]] = f"test{payload}"

        print(f"[*] Testing form at {target} with payload: {payload}")

        # Send POST or GET request accordingly
        if details["method"] == "post":
            res = s.post(target, data=data)
        else:
            res = s.get(target, params=data)

        # Check if response shows SQL error (possible vulnerability)
        if is_vulnerable(res):
            print(f"[!!!] SQL Injection vulnerability detected in form at {target} with payload: {payload}")
            results.append({
                "url": target,
                "payload": payload,
                "method": details["method"],
                "data": data
            })
            break  # Stop testing more payloads on this form once vulnerable

    return results


# Test URL parameters by injecting payloads one by one
def scan_url_parameters(url, payloads):
    print(f"[+] Testing URL parameters for {url}")
    parsed = urlparse(url)
    query = parse_qs(parsed.query)  # Extract query parameters as a dict

    vulnerable_points = []

    if not query:
        print("[*] No URL parameters to test.")
        return vulnerable_points

    # For each parameter, inject payloads and test
    for param in query:
        original_values = query.copy()
        for payload in payloads:
            injected_values = original_values.copy()
            # Inject payload by appending to the original parameter value
            injected_values[param] = [original_values[param][0] + payload]

            # Rebuild query string and full URL
            new_query = urlencode(injected_values, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            print(f"[*] Testing {new_url} with payload: {payload}")
            res = s.get(new_url)
            if is_vulnerable(res):
                print(f"[!!!] Potential SQL Injection found with param '{param}' and payload '{payload}'")
                vulnerable_points.append({
                    "url": new_url,
                    "param": param,
                    "payload": payload
                })
                break  # Stop testing more payloads on this param once vulnerable

    return vulnerable_points


# The main scanning function that combines form and URL param scanning
def scan_url(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} form(s) on {url}")
    payloads = load_payloads()
    final_results = []

    # Scan all forms found
    for form in forms:
        result = scan_form(url, form, payloads)
        final_results.extend(result)

    # Scan URL parameters
    url_results = scan_url_parameters(url, payloads)
    final_results.extend(url_results)

    # Save all potential vulnerabilities found into results.json
    with open("results.json", "w") as f:
        json.dump(final_results, f, indent=4)

    print(f"\n[✓] Scan complete. {len(final_results)} potential vulnerabilities saved to results.json")


# Script entry point: ask for URL and start scanning
if __name__ == "__main__":
    target_url = input("Please enter the URL to scan: ").strip()
    if not target_url:
        print("No URL entered, exiting.")
        exit(1)
    scan_url(target_url)
