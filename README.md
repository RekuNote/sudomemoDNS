![sudomemoDNS-MITM Logo](/sudomemoDNS-MITM_banner.png)

### sudomemoDNS-MITM is a fork of the original sudomemoDNS server, designed to act as a Man-In-The-Middle (MITM) proxy for DNS requests. This modified version captures and logs DNS requests and responses between your console and Sudomemo, allowing you to monitor and save the data exchanged during these interactions.

**Note:** This project currently does not have proper support for Windows.

## Setup

1. **Setup the Environment:**
    - Ensure you have Python 3.x installed.
    - Install required dependencies: `pip install dnslib requests`.

2. **Clone the Repository:**
    - `git clone https://github.com/yourusername/sudomemoDNS-MITM.git`
    - `cd sudomemoDNS-MITM`

3. **Run the Server:**
    - Ensure you have the necessary permissions to bind to UDP port 53.
    - Start the server: `sudo python3 sudomemoDNS-MITM.py`


## Features

- **MITM Logging:** Captures and logs all DNS requests and responses.
- **HTML Logging:** Generates an HTML file to view logs in a browser.
- **File Downloading:** Saves files transferred in DNS responses to the local filesystem.
- **Terminal Notifications:** Provides real-time logging and notifications in the terminal.## Getting Help

If you encounter any issues with sudomemoDNS-MITM, please open an issue in this repository. Do not open issues in the original sudomemoDNS repository if your issue is related to sudomemoDNS-MITM.
