import tkinter as tk
from tkinter import ttk, messagebox
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import requests, re, os, base64
from urllib.parse import urlparse
from PIL import Image, ImageTk
import threading
import pickle
import datetime
import time
import hashlib

# =============== GLOBAL STATE ===============
accounts = {}
hovered_row = None
last_selected = None
message_ids = {}  # Store message IDs by their table item ID

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid"
]

CREDENTIALS_FILE = "credentials.json"
TOKEN_FILE = "token.pickle"  # File to store authentication tokens

# =============== TOKEN MANAGEMENT ===============
def save_tokens():
    """Save all account tokens to file"""
    try:
        token_data = {}
        for email, creds in accounts.items():
            token_data[email] = {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
            }
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(token_data, token)
    except Exception as e:
        print("Error saving tokens:", e)

def load_tokens():
    """Load saved tokens from file"""
    global accounts
    try:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, 'rb') as token:
                token_data = pickle.load(token)
            
            for email, cred_data in token_data.items():
                from google.oauth2.credentials import Credentials
                creds = Credentials(
                    token=cred_data['token'],
                    refresh_token=cred_data['refresh_token'],
                    token_uri=cred_data['token_uri'],
                    client_id=cred_data['client_id'],
                    client_secret=cred_data['client_secret'],
                    scopes=cred_data['scopes']
                )
                accounts[email] = creds
                table.insert("", "end", values=(email,))
            return True
    except Exception as e:
        print("Error loading tokens:", e)
    return False

# =============== REPORT ===============
def save_malicious_urls_report(malicious_urls):
    """Save malicious URLs to a text file with timestamp"""
    if not malicious_urls:
        return
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"malicious_urls_report_{timestamp}.txt"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("MALICIOUS URLS REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            
            for i, (url, detection_count, service) in enumerate(malicious_urls, 1):
                f.write(f"{i}. URL: {url}\n")
                f.write(f"   Detected by: {detection_count} security engines\n")
                f.write(f"   Service: {service}\n")
                f.write(f"   Status: MALICIOUS 🚨\n")
                f.write("-" * 80 + "\n")
        
        print(f"Malicious URLs report saved as: {filename}")
    except Exception as e:
        print(f"Error saving report: {e}")

# =============== LOGIN GOOGLE ===============
def login_with_google():
    try:
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        creds = flow.run_local_server(port=4444)

        user_info = requests.get(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            headers={"Authorization": f"Bearer {creds.token}"}
        ).json()

        email = user_info.get("email", "unknown@user")
        if email in accounts:
            messagebox.showinfo("Info", f"{email} already added.")
            return

        accounts[email] = creds
        table.insert("", "end", values=(email,))
        save_tokens()  # Save tokens after successful login
        messagebox.showinfo("Success", f"Added Gmail account: {email}")

    except Exception as e:
        messagebox.showerror("Login Error", str(e))


# =============== FETCH EMAILS ===============
def show_emails(event):
    selected = table.focus()
    if not selected:
        return

    email = table.item(selected)["values"][0]
    creds = accounts[email]
    
    # Refresh token if expired
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(requests.Request())
        except Exception as e:
            print(f"Token refresh failed: {e}")
            return

    service = build("gmail", "v1", credentials=creds)

    # clear old
    for i in table1.get_children():
        table1.delete(i)
    for i in table2.get_children():
        table2.delete(i)
    message_ids.clear()

    try:
        results = service.users().messages().list(userId="me", maxResults=30).execute()
        messages = results.get("messages", [])
        if not messages:
            messagebox.showinfo("Info", f"No emails found for {email}")
            return

        for msg in messages:
            data = service.users().messages().get(
                userId="me", id=msg["id"], format="metadata",
                metadataHeaders=["From", "Subject", "Date"]
            ).execute()
            headers = data["payload"]["headers"]
            frm = next((h["value"] for h in headers if h["name"] == "From"), "")
            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No Subject)")
            date = next((h["value"] for h in headers if h["name"] == "Date"), "")
            
            item_id = table1.insert("", "end", values=(frm, subject, date))
            message_ids[item_id] = msg["id"]
            
        table1.service = service
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch emails: {str(e)}")


# =============== HOVER EFFECT ===============
def on_hover(event):
    global hovered_row
    row_id = table1.identify_row(event.y)
    if hovered_row == row_id:
        return

    # Clear previous hover
    if hovered_row and hovered_row != "":
        table1.item(hovered_row, tags=())
    
    hovered_row = row_id
    if row_id and row_id != "":
        table1.item(row_id, tags=("hover",))
        table1.tag_configure("hover", background="#f5f58a")


# =============== ANALYZE EMAIL ===============
def analyze_email(event):
    global last_selected
    selected = table1.focus()
    if not selected or selected == last_selected:
        return
    last_selected = selected

    # Get message ID from our dictionary
    msg_id = message_ids.get(selected)
    if not msg_id:
        return

    service = getattr(table1, "service", None)
    if not service:
        return

    try:
        msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
        payload = msg.get("payload", {})
        headers = payload.get("headers", [])
        body = get_body(payload)

        sender = next((h["value"] for h in headers if h["name"] == "From"), "")
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No Subject)")
        attachments = find_attachments(payload)
        urls = extract_urls(body)

        reasons, score = phishing_analysis(sender, subject, body, urls, attachments)
        update_analysis_table(reasons, score)

    except Exception as e:
        print("Analysis error:", e)


def update_analysis_table(reasons, score):
    for i in table2.get_children():
        table2.delete(i)
    for r in reasons:
        table2.insert("", "end", values=(r,))
    table2.insert("", "end", values=(f"Phishing Severity: {score}/100",))

    if score <= 30:
        table2.tag_configure("low", background="#d4edda")
        tag = "low"
    elif score <= 70:
        table2.tag_configure("medium", background="#fff3cd")
        tag = "medium"
    else:
        table2.tag_configure("high", background="#f8d7da")
        tag = "high"
    table2.item(table2.get_children()[-1], tags=(tag,))


# =============== FREE URL SCANNING SERVICES ===============

# Track malicious URLs for reporting
malicious_urls_found = []

def urlscan_io_scan(url):
    """urlscan.io - Free, no API key required, good rate limits"""
    try:
        # Submit URL for scanning
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'PhiWatch-Scanner/1.0'
        }
        data = {
            "url": url,
            "public": "on"
        }
        
        response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 429:
            return None, "Rate limit - try again later"
        elif response.status_code != 200:
            return None, f"Scan failed: {response.status_code}"
        
        result = response.json()
        scan_id = result.get('uuid')
        
        # Wait for result
        time.sleep(3)
        
        # Get verdict
        result_response = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_id}/",
            timeout=30
        )
        
        if result_response.status_code == 200:
            verdict_data = result_response.json()
            # Check for malicious indicators
            stats = verdict_data.get('stats', {})
            malicious_indicators = stats.get('malicious', 0)
            return malicious_indicators, "Success"
        
        return 0, "Clean"
        
    except Exception as e:
        return None, f"Error: {str(e)}"

def google_safebrowsing_check(url):
    """Google Safe Browsing - Free tier available"""
    try:
        # This is a simplified check - for full implementation you'd need API key
        # but we can check common malicious patterns
        suspicious_patterns = [
            'login.', 'verify.', 'security.', 'account.', 'update.',
            'password.', 'banking.', 'paypal.', 'amazon.'
        ]
        
        domain = urlparse(url).netloc.lower()
        for pattern in suspicious_patterns:
            if pattern in domain:
                return 1, "Suspicious pattern detected"
        
        return 0, "Clean"
    except Exception:
        return None, "Check failed"

def phishing_database_check(url):
    """Check against known phishing databases"""
    try:
        # Check URL against PhishTank (community driven)
        response = requests.get(
            f"http://checkurl.phishtank.com/checkurl/",
            params={'url': url},
            timeout=10
        )
        
        if response.status_code == 200:
            if 'phish' in response.text.lower():
                return 1, "PhishTank match"
        
        return 0, "Clean"
    except Exception:
        return None, "Database check failed"

def hybrid_analysis_check(url):
    """Hybrid Analysis - Free tier with good limits"""
    try:
        # Check if URL is in their database
        response = requests.get(
            f"https://www.hybrid-analysis.com/api/v2/overview/{hashlib.md5(url.encode()).hexdigest()}",
            headers={'User-Agent': 'Falcon Sandbox'},
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('verdict', '').lower() == 'malicious':
                return 1, "Hybrid Analysis: Malicious"
        
        return 0, "Clean"
    except Exception:
        return None, "Service unavailable"

def free_url_scan(url):
    """Try multiple free scanning services"""
    services = [
        ("🛡️ URLScan.io", urlscan_io_scan),
        ("🔍 Safe Browsing", google_safebrowsing_check),
        ("🐟 PhishTank", phishing_database_check),
        ("🔬 Hybrid Analysis", hybrid_analysis_check)
    ]
    
    for service_name, scan_function in services:
        try:
            result, message = scan_function(url)
            if result is not None:
                return result, message, service_name
            time.sleep(1)  # Be nice to the APIs
        except Exception:
            continue
    
    return None, "All services failed", "None"

def background_url_check(url):
    """Run URL scan in background using free services"""
    global malicious_urls_found
    
    result, message, service_name = free_url_scan(url)
    
    if result is None:
        verdict = f"❓ Scan Failed: {url}"
        color_tag = "neutral"
    elif result > 0:
        verdict = f"❌ MALICIOUS: {url} - {message} ({service_name})"
        color_tag = "malicious"
        # Add to malicious URLs list for reporting
        malicious_urls_found.append((url, result, service_name))
    else:
        verdict = f"✅ CLEAN: {url} - {service_name}"
        color_tag = "clean"
    
    # Update UI in main thread
    window.after(0, lambda: update_scan_result(verdict, color_tag))

def update_scan_result(verdict, color_tag):
    """Update the table with scan results and apply color coding."""
    table2.insert("", "end", values=(verdict,))
    
    # Configure colors for different result types
    if color_tag == "malicious":
        table2.tag_configure("malicious", background="#ffcccc")  # Light red
        table2.item(table2.get_children()[-1], tags=("malicious",))
    elif color_tag == "clean":
        table2.tag_configure("clean", background="#ccffcc")  # Light green
        table2.item(table2.get_children()[-1], tags=("clean",))
    elif color_tag == "neutral":
        table2.tag_configure("neutral", background="#ffffcc")  # Light yellow
        table2.item(table2.get_children()[-1], tags=("neutral",))


# =============== HELPERS ===============
def get_body(payload):
    if "body" in payload and "data" in payload["body"]:
        try:
            return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    for part in payload.get("parts", []):
        text = get_body(part)
        if text:
            return text
    return ""


def find_attachments(payload):
    files = []
    for part in payload.get("parts", []):
        name = part.get("filename")
        if name:
            files.append(name)
    return files


def extract_urls(text):
    return re.findall(r"https?://[^\s>]+", text)


def extract_domain_from_email(email):
    """Extract domain from email address."""
    match = re.search(r'@([\w.-]+)', email)
    return match.group(1).lower() if match else ""


def extract_main_domain(domain):
    """Extract main domain (without subdomains) using public suffix list logic."""
    parts = domain.split('.')
    if len(parts) >= 2:
        if len(parts) > 2 and parts[-2] in {'co', 'com', 'org', 'net', 'gov', 'ac'}:
            return parts[-3] if len(parts) > 2 else parts[-2]
        return parts[-2]
    return domain


def is_suspicious_domain_mismatch(sender_domain, url_domain):
    """Improved domain mismatch detection."""
    if not sender_domain or not url_domain:
        return False
    
    sender_main = extract_main_domain(sender_domain)
    url_main = extract_main_domain(url_domain)
    
    if sender_main == url_main:
        return False
    
    legitimate_services = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'fb.me', 'ow.ly',
        'buff.ly', 'tiny.cc', 'is.gd', 'cli.gs', 'youtu.be', 'amzn.to',
        'rebrand.ly', 'linktr.ee', 'page.link', 'lit.link', 'cutt.ly'
    }
    
    if url_domain in legitimate_services:
        return False
    
    email_service_domains = {
        'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
        'protonmail.com', 'icloud.com', 'mail.com', 'zoho.com', 'gmx.com'
    }
    
    if sender_domain in email_service_domains:
        return False
    
    shortener_indicators = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'buff.ly', 
                           'is.gd', 'cli.gs', 'youtu.be', 'amzn.to', 'cutt.ly', 'rebrand.ly']
    
    if any(indicator in url_domain for indicator in shortener_indicators):
        return False
    
    return True


# =============== PHISHING LOGIC ===============
def phishing_analysis(sender, subject, body, urls, attachments):
    global malicious_urls_found
    score = 0
    reasons = []

    # Reset malicious URLs list for new analysis
    malicious_urls_found = []

    # 1. Bait / urgency
    urgency_keywords = ["urgent", "immediately", "action required", "verify now", "account suspended", 
                       "password expired", "security alert", "limited time", "last chance", "final notice"]
    if any(w in body.lower() for w in urgency_keywords):
        reasons.append("Contains urgency or bait language.")
        score += 5

    # 2. Suspicious attachments
    suspicious_extensions = [".exe", ".bat", ".scr", ".js", ".vbs", ".ps1", ".jar", ".com", ".pif", ".cpl"]
    for a in attachments:
        if any(a.lower().endswith(ext) for ext in suspicious_extensions):
            reasons.append(f"Suspicious attachment: {a}")
            score += 10
        elif any(a.lower().endswith(ext) for ext in [".zip", ".rar", ".7z"]):
            reasons.append(f"Compressed attachment (may contain malicious files): {a}")
            score += 10

    # 3. Domain analysis
    sender_domain = extract_domain_from_email(sender)
    
    for u in urls:
        parsed = urlparse(u)
        url_domain = parsed.netloc.lower()
        
        if is_suspicious_domain_mismatch(sender_domain, url_domain):
            reasons.append(f"Suspicious domain mismatch: sender uses '{sender_domain}' but links to '{url_domain}'")
            score += 5

        homograph_chars = ["а", "е", "і", "о", "р", "ѕ", "с", "у", "х", "ј", "ѵ", "ԛ", "ԍ", "ԁ", "і"]
        if any(ch in url_domain for ch in homograph_chars):
            reasons.append(f"Possible homograph domain detected: {url_domain}")
            score += 10

    # 4. Suspicious keywords in body
    suspicious_phrases = ["click here", "login now", "update your account", "confirm your identity", 
                         "unusual activity", "verify your account", "banking details", "social security"]
    if any(phrase in body.lower() for phrase in suspicious_phrases):
        reasons.append("Contains suspicious phrases commonly used in phishing.")
        score += 3

    # 5. Free URL scanning services
    if urls:
        reasons.append("Scanning URLs with free security services...")
        for u in urls:
            threading.Thread(target=background_url_check, args=(u,), daemon=True).start()

    if not reasons:
        reasons.append("No suspicious indicators detected.")
    return reasons, min(score, 100)


# =============== UI ===============
window = tk.Tk()
window.title("PhiWatch")
window.geometry("1500x750")
window.configure(bg="#f4f6f8")
window.iconbitmap('ico.ico')

# Configure column weights to make the reason column wider
window.columnconfigure(0, weight=1)   # Accounts column
window.columnconfigure(1, weight=2)   # Emails column  
window.columnconfigure(2, weight=3)   # Reason column (wider)
window.rowconfigure(0, weight=1)

try:
    google_image = Image.open("google.png").resize((30, 30))
    google_image_tk = ImageTk.PhotoImage(google_image)
except Exception:
    google_image_tk = None

# Add a button to generate malicious URLs report
def generate_report():
    if malicious_urls_found:
        save_malicious_urls_report(malicious_urls_found)
        messagebox.showinfo("Report Generated", f"Malicious URLs report saved with {len(malicious_urls_found)} entries.")
    else:
        messagebox.showinfo("No Malicious URLs", "No malicious URLs found to report.")

report_btn = ttk.Button(window, text="Generate Malicious URLs Report", command=generate_report)
report_btn.grid(row=1, column=2, sticky="we", padx=8, pady=8)

login_btn = ttk.Button(window, text="Login with Google", image=google_image_tk,
                       compound="left", command=login_with_google)
login_btn.grid(row=1, column=0, sticky="we", padx=8, pady=8)

# Accounts table (narrower)
table = ttk.Treeview(window, columns=("email",), show="headings", height=18)
table.heading("email", text="Connected")
table.column("email", width=200)  # Fixed width for accounts
table.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
table.bind("<<TreeviewSelect>>", show_emails)

# Emails table (medium width)
table1 = ttk.Treeview(window, columns=("from", "subject", "date"), show="headings", height=18)
table1.heading("from", text="From")
table1.heading("subject", text="Subject")
table1.heading("date", text="Date")
table1.column("from", width=200)
table1.column("subject", width=300)
table1.column("date", width=150)
table1.grid(row=0, column=1, sticky="nsew", rowspan=2, padx=5, pady=5)
table1.bind("<<TreeviewSelect>>", analyze_email)
table1.bind("<Motion>", on_hover)

# Analysis results table (wider WITHOUT scrollbars)
table2 = ttk.Treeview(window, columns=("reason",), show="headings", height=18)
table2.heading("reason", text="Phishing Indicators")
table2.column("reason", width=600)
table2.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)

# Load saved tokens on startup
load_tokens()

window.mainloop()