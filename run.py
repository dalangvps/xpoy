import requests
import re
import sys
import time
from urllib.parse import urljoin, urlparse
from collections import deque

# Warna ala gangster CI
W_RED = '\033[91m'
W_GREEN = '\033[92m'
W_YELLOW = '\033[93m'
W_BLUE = '\033[94m'
W_CYAN = '\033[96m'
W_RESET = '\033[0m'

# Daftar Payload yang Lebih Brutal
PAYLOADS = {
    "SQLi_Error": ["'", '"', " OR 1=1--"], # Payload buat memicu error SQL
    "XSS_Reflected": ["<scRiPt>alert('Xpoy')</scRipt>", '"><img src=x onerror=alert("Xpoy")>', "javascript:alert(1)"], # Payload XSS
    "LFI_Basic": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"] # Payload LFI
}

# Ekstensi file yang harus diabaikan saat crawling
IGNORE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.css', '.js', '.ico', '.zip', '.rar', '.mp4', '.mp3']

# Parameter yang biasanya tidak vuln (untuk efisiensi)
IGNORE_PARAMS = ['PHPSESSID', 'JSESSIONID', 'sessionid', 'utm_source', 'gclid']

class XpoyScanner:
    def __init__(self, target_url):
        self.target_url = self._normalize_url(target_url)
        self.base_domain = urlparse(self.target_url).netloc
        self.visited_urls = set()
        self.vuln_found = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Referer': self.target_url
        })

    def _normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def _should_ignore_link(self, link):
        """Cek apakah link adalah file statis atau domain berbeda"""
        parsed_link = urlparse(link)

        # Cek domain
        if parsed_link.netloc != self.base_domain:
            return True

        # Cek ekstensi statis
        if any(link.lower().endswith(ext) for ext in IGNORE_EXTENSIONS):
            return True

        return False

    def _get_links_and_params(self, content, current_url):
        """Ekstrak semua link dan parameter yang relevan dari konten"""
        links = set()
        params = set()

        # 1. Ekstrak Link (href)
        href_links = re.findall(r'href=["\'](.*?)(?=["\'])', content)
        for link in href_links:
            abs_link = urljoin(current_url, link)
            if not self._should_ignore_link(abs_link) and abs_link not in self.visited_urls:
                # Bersihkan URL dari fragment (#...) sebelum disimpan
                clean_link = urlparse(abs_link)._replace(fragment='').geturl()
                links.add(clean_link)

            # Ekstrak parameter dari query string link ini
            parsed_link = urlparse(abs_link)
            if parsed_link.query:
                query_params = re.findall(r'([^=&]+)=', parsed_link.query)
                for p in query_params:
                    if p not in IGNORE_PARAMS:
                        params.add(p)

        # 2. Ekstrak parameter dari FORM inputs
        # Cari input/textarea/select name
        form_params = re.findall(r'<input[^>]*name=["\']?([^"\'\s>]+)', content, re.IGNORECASE)
        form_params.extend(re.findall(r'<textarea[^>]*name=["\']?([^"\'\s>]+)', content, re.IGNORECASE))
        form_params.extend(re.findall(r'<select[^>]*name=["\']?([^"\'\s>]+)', content, re.IGNORECASE))

        for p in set(form_params):
            if p not in IGNORE_PARAMS:
                params.add(p)

        return links, params

    def _test_vulnerability(self, url, param, payload_type, payload):
        """Melakukan uji injeksi pada parameter URL"""

        # Fungsi untuk mengganti nilai parameter di URL
        if '?' not in url:
            test_url = f"{url}?{param}={payload}"
        else:
            pattern = re.escape(param) + r'=[^&]*'
            if re.search(pattern, url):
                test_url = re.sub(pattern, f"{param}={payload}", url)
            else:
                test_url = f"{url}&{param}={payload}"

        try:
            # 1. Cek SQLi Error
            if payload_type == "SQLi_Error":
                response = self.session.get(test_url, timeout=7)
                content = response.text
                if any(err in content for err in ['syntax error', 'mysql_fetch', 'unclosed quotation mark', 'supplied argument is not a valid', 'Microsoft OLE DB Provider for ODBC Drivers']):
                    return f"SQLi (Error Message)", test_url

            # 2. Cek XSS Reflected
            elif payload_type == "XSS_Reflected":
                # URL encode payload agar lolos di request, tapi tetap cek payload aslinya di response
                encoded_payload = requests.utils.quote(payload)
                test_url_xss = test_url.replace(payload, encoded_payload)

                response = self.session.get(test_url_xss, timeout=7)
                content = response.text

                # Cek jika payload (case-insensitive) terpantul di response
                if payload.lower() in content.lower():
                    return f"XSS (Reflected)", test_url_xss

            # 3. Cek LFI
            elif payload_type == "LFI_Basic":
                response = self.session.get(test_url, timeout=7)
                content = response.text
                if ('root:x' in content and 'daemon:x' in content) or ('[drivers]' in content and '[Micrósóft]' in content):
                    return f"LFI (Local File Inclusion)", test_url

        except requests.exceptions.RequestException:
            pass
        return None, None

    def start_scan(self):
        """Memulai proses crawling dan scanning"""

        print(f"{W_YELLOW}[*] Memulai Xpoy Crawling dan Scanning di: {self.target_url}{W_RESET}")

        urls_to_visit = deque([self.target_url])
        self.visited_urls.add(self.target_url)

        while urls_to_visit and len(self.visited_urls) < 500: # Batas crawl 500 URL untuk keamanan dan kecepatan
            current_url = urls_to_visit.popleft()
            print(f"{W_CYAN}[+] Crawling/Scanning: {current_url}{W_RESET}")

            try:
                response = self.session.get(current_url, timeout=15, allow_redirects=True)
                response.raise_for_status()
                content = response.text

                # 1. Ekstrak Link dan Parameter
                new_links, parameters = self._get_links_and_params(content, current_url)

                for link in new_links:
                    if link not in self.visited_urls:
                        self.visited_urls.add(link)
                        urls_to_visit.append(link)

                # 2. Uji Kerentanan pada semua Parameter yang ditemukan
                if parameters:
                    print(f"  {W_YELLOW}[*] Parameter Ditemukan ({len(parameters)}): {', '.join(parameters)}{W_RESET}")

                    for param in parameters:
                        # Iterasi di semua tipe payload
                        for payload_type, payloads in PAYLOADS.items():
                            for payload in payloads:
                                vuln_type, proof_url = self._test_vulnerability(current_url, param, payload_type, payload)

                                if vuln_type:
                                    self.vuln_found.append((vuln_type, param, proof_url))
                                    print(f"    {W_RED}>>> VULNERABILITY DITEMUKAN: {vuln_type} di parameter '{param}'{W_RESET}")
                                    print(f"    {W_RED}>>> BUKTI URL: {proof_url}{W_RESET}")
                                    # Hentikan testing parameter ini jika sudah ketemu vuln
                                    break
                            if vuln_type:
                                break

            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass

        self.display_summary()

    def display_summary(self):
        """Menampilkan rangkuman hasil scan"""
        print(f"\n{W_BLUE}===================================================={W_RESET}")
        print(f"{W_RED}*** LAPORAN AKHIR XPOY PROFESSIONAL ({self.target_url}) ***{W_RESET}")
        print(f"{W_BLUE}===================================================={W_RESET}")
        print(f"{W_GREEN}[+] Total Halaman yang Di-crawl: {len(self.visited_urls)}{W_RESET}")
        print(f"{W_RED}[!!!] Total Kerentanan Ditemukan: {len(self.vuln_found)}{W_RESET}")

        if self.vuln_found:
            print(f"\n{W_RED}*** BUKTI KERENTANAN (PROOF OF VULN) ***{W_RESET}")
            for vuln, param, url in self.vuln_found:
                print(f"[{vuln}] Parameter: {param}")
                print(f"  {W_YELLOW}-> Bukti URL:{W_RESET} {url}")
            print(f"*****************************************{W_RESET}")
        else:
            print(f"{W_GREEN}[*] Tidak ada kerentanan dasar yang ditemukan. Lanjut ke Fuzzing dan Blind Testing!{W_RESET}")

def banner():
    print(f"""{W_RED}
 ===============================
|  XPOY :: By GhostF4j          |
|  github :: DalangVps          |
|——————————————————————————————–|
| Tools ini dibuat untuk        |
| keamanan cyber, Tools ini     |
| di rancang untuk memudahkan   |
| pengguna untuk mengecek suatu |
| aplikasi website.             |
 ===============================
{W_BLUE} Xpoy v2.0
{W_RESET}""")

if __name__ == "__main__":
    banner()
    if len(sys.argv) != 3 or sys.argv[1] != '-u':
        print(f"[*] Cara pake: python run.py -u <URL_TARGET>")
        print(f"[*] Contoh: python run.py -u https://target.com/index.php?id=1")
    else:
        target_url = sys.argv[2]
        scanner = XpoyScanner(target_url)
        scanner.start_scan()