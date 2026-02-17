import requests  # For making HTTP requests
from bs4 import BeautifulSoup  # For parsing HTML
from urllib.parse import urljoin, urlparse  # For handling URLs
import sys  # For command-line arguments

# Function to extract all forms from a webpage
def get_forms(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = []
        for form in soup.find_all('form'):
            details = {}
            action = form.attrs.get('action')
            method = form.attrs.get('method', 'get').lower()
            inputs = []
            for input_tag in form.find_all('input'):
                input_type = input_tag.attrs.get('type', 'text')
                input_name = input_tag.attrs.get('name')
                if input_name:
                    inputs.append({'type': input_type, 'name': input_name})
            details['action'] = urljoin(url, action) if action else url
            details['method'] = method
            details['inputs'] = inputs
            forms.append(details)
        return forms
    except Exception as e:
        print(f"Error fetching forms from {url}: {e}")
        return []

# Function to submit a form with a given payload
def submit_form(form_details, url, payload):
    target_url = form_details['action']
    inputs = form_details['inputs']
    data = {}
    for input in inputs:
        if input['type'] == 'text' or input['type'] == 'search' or input['type'] == 'email':
            data[input['name']] = payload
        else:
            data[input['name']] = 'test'  # Fallback value for non-text inputs
    if form_details['method'] == 'post':
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

# Function to test for XSS vulnerability
def test_xss(url, form_details):
    payload = "<script>alert('xss')</script>"  # Basic XSS payload
    response = submit_form(form_details, url, payload)
    if payload in response.text:
        return True  # Reflected XSS detected
    return False

# Function to test for SQL Injection vulnerability
def test_sqli(url, form_details):
    payload = "' OR '1'='1"  # Basic SQLi payload
    response = submit_form(form_details, url, payload)
    errors = ["sql syntax", "mysql", "sqlite", "postgresql", "warning: mysql"]  # Common error indicators
    for error in errors:
        if error in response.text.lower():
            return True  # SQL error detected
    # Check for bypass success (e.g., unauthorized access)
    if "welcome" in response.text.lower() or "logged in" in response.text.lower():
        return True
    return False

# Function to crawl the site and scan forms (recursive, with visit tracking)
def crawl_and_scan(url, visited=None):
    if visited is None:
        visited = set()
    if url in visited:
        return
    visited.add(url)
    print(f"Scanning: {url}")
    forms = get_forms(url)
    for i, form in enumerate(forms, 1):
        print(f"Form {i} at {url}:")
        if test_xss(url, form):
            print(" - XSS Vulnerable!")
        if test_sqli(url, form):
            print(" - SQLi Vulnerable!")
    
    # Find and crawl internal links (basic crawler)
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.attrs.get('href')
            if href:
                next_url = urljoin(url, href)
                if urlparse(next_url).netloc == urlparse(url).netloc and next_url not in visited:
                    crawl_and_scan(next_url, visited)
    except Exception as e:
        print(f"Error crawling {url}: {e}")

# Main entry point
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python web_vuln_scanner.py [url]")
        sys.exit(1)
    url = sys.argv[1]
    crawl_and_scan(url)