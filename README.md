# FinderBuster

## OSINT Tool for Username Reconnaissance, Domain Information, and Social Media Profiling

FinderBuster is a powerful OSINT (Open Source Intelligence) tool designed to help security researchers, penetration testers, and digital investigators gather information about usernames, domains, and social media profiles.

```
███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ 
██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

## Features

- **Username Search**: Check if a username exists across 13+ popular social media platforms and websites
- **Domain Information**: Gather extensive information about domains including WHOIS, DNS records, IP details, and HTTP headers
- **Social Media Profiling**: Extract profile information from Instagram, Twitter/X, GitHub, and LinkedIn

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/nieliebert/finderbuster.git
cd finderbuster
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

### Dependencies

The following Python packages are required:
- requests
- beautifulsoup4
- colorama
- python-whois
- dnspython

## Usage

FinderBuster has three main commands:

### 1. Username Search

Search for a username across multiple social media platforms and websites:

```bash
python finderbuster.py username <username>
```

Example:
```bash
python finderbuster.py username johndoe
```

### 2. Domain Information

Gather comprehensive information about a domain:

```bash
python finderbuster.py domain <domain>
```

Example:
```bash
python finderbuster.py domain example.com
```

### 3. Social Media Profiling

Extract profile information from a specific social media platform:

```bash
python finderbuster.py social <platform> <identifier>
```

Supported platforms: `instagram`, `twitter`, `x`, `github`, `linkedin`

Example:
```bash
python finderbuster.py social github octocat
```

### View Tool Version

```bash
python finderbuster.py --version
```

## Output

Results are saved in the `finderbuster_results` directory in JSON format with timestamped filenames. This allows for easy analysis and comparison of results over time.

## Supported Platforms for Username Search

- Instagram
- Twitter/X
- Facebook
- TikTok
- YouTube
- LinkedIn
- Reddit
- Pinterest
- GitHub
- Tumblr
- Medium
- Quora
- Twitch

## Supported Platforms for Profile Extraction

- Instagram
- Twitter/X
- GitHub
- LinkedIn

## Domain Information Gathered

- WHOIS data (registrar, creation date, expiration date, etc.)
- DNS records (A, AAAA, MX, NS, TXT, CNAME)
- IP address and geolocation
- HTTP server information and headers
- Redirect chains

## Example

```bash
# Search for username "jhondoe" across platforms
$ python finderbuster.py username jhondoe

# Check information for domain "example.org"
$ python finderbuster.py domain example.org

# Extract GitHub profile information for user "jhondoe"
$ python finderbuster.py social github jhondoe
```


## Limitations

- Instagram, Twitter, and LinkedIn limit the amount of information available without authentication
- Some websites may implement rate limiting or blocking of automated requests
- The tool respects robots.txt and is intended for legitimate security research purposes only

## Legal Disclaimer

This tool is provided for educational and research purposes only. Users are responsible for complying with applicable laws and terms of service when using this tool. The developer assumes no liability for misuse of this software or for damages resulting from its use.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Created by NunoGans (2025)

## Acknowledgments

- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) for HTML parsing
- [Requests](https://requests.readthedocs.io/) for HTTP requests
- [python-whois](https://pypi.org/project/python-whois/) for WHOIS information
- [dnspython](https://www.dnspython.org/) for DNS information
