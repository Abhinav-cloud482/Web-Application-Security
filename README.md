# Web-Application-Security

A lightweight, automated Python tool designed to crawl web applications and identify common security vulnerabilities. This scanner performs deep-link discovery and tests endpoints for injection flaws and sensitive data exposure.

## Features
- Recursive Web Crawling : Automatically discovers internal links up to a user-defined depth.

- SQL Injection Detection : Tests GET parameters using common payloads to identify database error leakage.

- XSS Testing : Checks for Cross-Site Scripting vulnerabilities by injecting scripts and verifying if they are reflected in the response.

- Sensitive Data Exposure : Uses Regular Expressions (Regex) to find leaked emails, phone numbers, SSNs, and API keys.

- Multithreaded Execution : Utilizes ThreadPoolExecutor for high-performance concurrent scanning.

- Colored Terminal Output : Provides easy-to-read, color-coded results using colorama.

## Installation
1. Clone the repository :-

```
git clone https://github.com/your-username/WebSecurityScanner.git
cd WebSecurityScanner
```

2. Install dependencies :-

This project requires Python 3.x and the following libraries :-

```
pip install requests beautifulsoup4 colorama
```

## Usage
Run the script from your terminal :-

```
python scanner.py
```

Configuration Steps :-

1. Target URL : Enter the full URL (e.g., http://example.com).

2. Crawl Depth : Set how many levels of links the crawler should follow (default is 3).

3. Select Modules : Toggle specific checks (SQLi, XSS, Sensitive Info) on or off.

## How it Works
1. Crawling Phase : The WebSecurityScanner class uses BeautifulSoup to parse HTML and extract all <a> tags, building a map of the site within the specified domain.

2. Scanning Phase : * SQLi : Appends payloads like ' OR 1=1-- to parameters and monitors for database-specific error strings.

    -  XSS : Injects <script> tags and checks if the exact string is returned in the HTML body.

    -  Sensitive Data : Scans the raw response text against a dictionary of predefined regex patterns.

3. Reporting : Vulnerabilities are printed in real-time to the console and summarized at the end of the session.

## Disclaimer

Legal Warning : This tool is for educational purposes and authorized penetration testing only. Running this scanner against a website you do not have explicit written permission to test is illegal. The author is not responsible for any misuse or damage caused by this program.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Abhinav Dixit

Python Developer | Data & ML Enthusiast

- Feel free to fork, star, or contribute to this project!
