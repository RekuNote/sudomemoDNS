import os
import json
import threading
from datetime import datetime, timezone
from socket import socket, AF_INET, SOCK_DGRAM, gethostbyname
from sys import platform
from time import sleep
from dnslib import A, DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE, DNSLabel, DNSBuffer
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger
from requests import get, RequestException, Timeout

BASE_VERSION = "1.2.1"
MITM_VERSION = "v0.1.8"

# Ensure directories exist
os.makedirs('files/mitm/', exist_ok=True)
os.makedirs('files/', exist_ok=True)

log_html_path = 'files/log.html'

# Create HTML file with JavaScript for live update
html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Request Log</title>
    <style>
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid black; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .export-button { margin-top: 20px; padding: 10px 20px; }
    </style>
</head>
<body>
    <h2>Request Log</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Request Type</th>
                <th>Data</th>
            </tr>
        </thead>
        <tbody id="request-log">
        </tbody>
    </table>
    <h2>Downloaded Files</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Filename</th>
                <th>URL</th>
            </tr>
        </thead>
        <tbody id="file-log">
        </tbody>
    </table>
    <button class="export-button" onclick="exportLogs()">Export as .txt</button>
    <script>
        function appendLog(entry) {
            const requestLog = document.getElementById('request-log');
            const fileLog = document.getElementById('file-log');
            if (entry.event === 'file_download') {
                const row = `<tr>
                    <td>${entry.timestamp}</td>
                    <td>${entry.filename}</td>
                    <td>${entry.url}</td>
                </tr>`;
                fileLog.innerHTML += row;
            } else {
                const row = `<tr>
                    <td>${entry.timestamp}</td>
                    <td>${entry.request_type}</td>
                    <td>${entry.data}</td>
                </tr>`;
                requestLog.innerHTML += row;
            }
        }

        function exportLogs() {
            const requestLog = document.getElementById('request-log').innerText;
            const fileLog = document.getElementById('file-log').innerText;
            const logs = requestLog + "\\n\\n" + fileLog;
            const blob = new Blob([logs], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'logs.txt';
            a.click();
            URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>
"""

def create_html_file():
    with open(log_html_path, 'w') as log_file:
        log_file.write(html_content)
    print(f"[MITM] HTML logs file generated at {os.path.abspath(log_html_path)}.")

create_html_file()

def get_platform():
    platforms = {
        'linux1': 'Linux',
        'linux2': 'Linux',
        'darwin': 'macOS',
        'win32': 'Windows'
    }
    if platform not in platforms:
        return platform

    return platforms[platform]

def format_ip(address):
    octets = str(address).split(".")
    return f"{int(octets[0]):03d}.{int(octets[1]):03d}.{int(octets[2]):03d}.{int(octets[3]):03d}"

def get_ip():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def log_request(request_type, data):
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
    log_entry = {
        "timestamp": timestamp,
        "request_type": request_type,
        "data": data
    }
    append_log_to_html(log_entry, "request-log")

def log_file_download(filename, url):
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
    log_entry = {
        "timestamp": timestamp,
        "event": "file_download",
        "filename": filename,
        "url": url
    }
    append_log_to_html(log_entry, "file-log")

def append_log_to_html(log_entry, log_type):
    with open(log_html_path, 'r+') as log_file:
        content = log_file.read()
        if log_type == "request-log":
            index = content.index("</tbody>", content.index('<tbody id="request-log">')) + len("</tbody>")
        else:
            index = content.index("</tbody>", content.index('<tbody id="file-log">')) + len("</tbody>")
        
        log_file.seek(index)
        log_file.write("</tbody></table>")
        log_file.seek(index)
        
        if log_entry.get('event') == 'file_download':
            log_file.write(f"<tr><td>{log_entry['timestamp']}</td><td>{log_entry['filename']}</td><td>{log_entry['url']}</td></tr>")
        else:
            log_file.write(f"<tr><td>{log_entry['timestamp']}</td><td>{log_entry['request_type']}</td><td>{log_entry['data']}</td></tr>")
        
        log_file.write(content[index:])
        print(f"[MITM] Added logs to HTML logs file at {os.path.abspath(log_html_path)}.")

def save_file(filename, content):
    filepath = os.path.join('files/mitm', filename)
    with open(filepath, 'wb') as file:
        file.write(content)

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
SERIAL = int((datetime.now(timezone.utc) - EPOCH).total_seconds())
MY_IP = get_ip()

print("\n== Hello from RexiMemo! ==\n")

print("+==============================+")
print("|   Sudomemo DNS MITM Server   |")
print(f"|       Base Ver {BASE_VERSION}         |")
print(f"|       MITM Ver {MITM_VERSION}        |")
print("+==============================+\n")

print("== Welcome to sudomemoDNS-MITM! ==")
print("This server is a modified version of sudomemoDNS that allows you to capture requests and responses between your console and Sudomemo.\n")

print("== How To Use ==")
print("First, make sure that your console is connected to the same network as this computer.\n")

print("Then, put these settings in for DNS on your console:")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
print(f"Primary DNS:   {format_ip(MY_IP)}")
print("Secondary DNS: 008.008.008.008")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

print("== Getting Help ==")
print("Need help? Visit our Discord server at https://www.reximemo.net/discord and message Rekushi.\n")

print("== Shameless Plug ==")
print("Using this tool because you're setting up your own Flipnote Hatena server that's not proprietary like Sudomemo? Consider RexiMemo, an open source alternative! @ https://www.reximemo.net/\n")

print("[INFO] Starting sudomemoDNS-MITM...")

TYPE_LOOKUP = {
    A: QTYPE.A,
}

class SudomemoDNSLogger(DNSLogger):
    def log_request(self, handler, request):
        client_ip = handler.client_address[0]
        print(f"\n[REQUEST] Console made request:\n\"{request}\"")
        log_request("DNS Request", str(request))

    def log_reply(self, handler, reply):
        client_ip = handler.client_address[0]
        print(f"\n[RESPONSE] Server responded to console with:\n{reply}.")
        log_request("DNS Response", str(reply))

        # Check for files in the DNS response and save them
        for rr in reply.rr:
            if rr.rdata:
                domain = str(rr.rname).strip('.')
                # Extract file name and extension from the domain or default to .dat if not possible
                if '.' in domain:
                    filename = f"{client_ip}_{domain}"
                else:
                    filename = f"{client_ip}_{domain}.dat"
                buffer = DNSBuffer()
                rr.rdata.pack(buffer)
                save_file(filename, buffer.data)
                log_file_download(filename, domain)
                print(f"\n[RESPONSE] Server responded to console with {filename}. Saved to files/mitm/{filename}.")

    def log_error(self, handler, e):
        print(f"\n[ERROR] Invalid DNS request from {handler.client_address[0]}: {e}")

    def log_truncated(self, handler, reply):
        pass

    def log_data(self, dnsobj):
        pass

class Record:
    def __init__(self, rdata_type, *args, rtype=None, rname=None, ttl=None, **kwargs):
        self._rtype = TYPE_LOOKUP[rdata_type]
        rdata = rdata_type(*args)
        if rtype:
            self._rtype = rtype
        self._rname = rname
        self.kwargs = dict(
            rdata=rdata,
            ttl=self.sensible_ttl() if ttl is None else ttl,
            **kwargs,
        )

    def try_rr(self, q):
        if q.qtype == QTYPE.ANY or q.qtype == self._rtype:
            return self.as_rr(q.qname)

    def as_rr(self, alt_rname):
        return RR(rname=self._rname or alt_rname, rtype=self._rtype, **self.kwargs)

    def sensible_ttl(self):
        if self._rtype in (QTYPE.NS, QTYPE.SOA):
            return 60 * 60 * 24
        else:
            return 300

    @property
    def is_soa(self):
        return self._rtype == QTYPE.SOA

    def __str__(self):
        return '{} {}'.format(QTYPE[self._rtype], self.kwargs)

ZONES = {}

try:
    get_zones = get("https://www.sudomemo.net/api/dns_zones.json",
                    headers={'User-Agent': 'SudomemoDNS/' + BASE_VERSION + 'sudomemoDNS-MITM/' + MITM_VERSION + ' (' + get_platform() + ')'})
    get_zones.raise_for_status()
    zones = json.loads(get_zones.text)
except Timeout:
    print("[ERROR] Unable to load DNS data: Connection to Sudomemo timed out. Are you connected to the Internet?")
    exit(1)
except RequestException as e:
    print("[ERROR] Unable load DNS data.")
    print("[ERROR] Exception: ", e)
    exit(1)
except ValueError as e:
    print("[ERROR] Unable load DNS data: Invalid response from server. Check that you can visit sudomemo.net without errors.")
    exit(1)

for zone in zones:
    if zone["type"] == "a":
        ZONES[zone["name"]] = [Record(A, zone["value"])]
    elif zone["type"] == "p":
        ZONES[zone["name"]] = [Record(A, gethostbyname(zone["value"]))]

print("[INFO] DNS information loaded successfully.")
print("[INFO] Setting up MITM...")

class Resolver(BaseResolver):
    def __init__(self):
        self.zones = {DNSLabel(k): v for k, v in ZONES.items()}

    def resolve(self, request, handler):
        reply = request.reply()
        zone = self.zones.get(request.q.qname)

        if zone is not None:
            for zone_records in zone:
                rr = zone_records.try_rr(request.q)
                rr and reply.add_answer(rr)
        else:
            for zone_label, zone_records in self.zones.items():
                if request.q.qname.matchSuffix(zone_label):
                    try:
                        soa_record = next(r for r in zone_records if r.is_soa)
                    except StopIteration:
                        continue
                    else:
                        reply.add_answer(soa_record.as_rr(zone_label))
                        break

        return reply

resolver = Resolver()
dnsLogger = SudomemoDNSLogger()

print("[INFO] Detected operating system:", get_platform())

if get_platform() == 'linux':
    print("[INFO] Please note that you will have to run this as root or with permissions to bind to UDP port 53.")
    print("[INFO] If you aren't seeing any requests, check that this is the case first with lsof -i:53 (requires lsof)")
    print("[INFO] To run as root, prefix the command with 'sudo'")
elif get_platform() == 'macOS':
    print("[INFO] Please note that you will have to run this as root or with permissions to bind to UDP port 53.")
    print("[INFO] If you aren't seeing any requests, check that this is the case first with lsof -i:53 (requires lsof)")
    print("[INFO] To run as root, prefix the command with 'sudo'")
elif get_platform() == 'Windows':
    print("[INFO] Please note that you may have to allow this application through the firewall. If so, a popup will appear in a moment.")
    print("[INFO] If you are not seeing any requests, make sure you have allowed this application through the firewall. If you have already done so, disregard this message.")

try:
    servers = [
        DNSServer(resolver=resolver, port=53, address=MY_IP, tcp=True, logger=dnsLogger),
        DNSServer(resolver=resolver, port=53, address=MY_IP, tcp=False, logger=dnsLogger)
    ]
except PermissionError:
    print("[ERROR] Permission error: Check that you are running this as an administrator or root")
    exit(1)

print("[INFO] sudomemoDNS-MITM is ready. Now waiting for DNS requests from your console...")

def start_dns():
    for s in servers:
        s.start_thread()

    try:
        while 1:
            sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.stop()

if __name__ == '__main__':
    threading.Thread(target=start_dns).start()
