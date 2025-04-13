#!/usr/bin/env python3
# FinderBuster - OSINT Tool for Username Reconnaissance, Domain Information, and Social Media Profiling
# Created: April 2025

import argparse
import concurrent.futures
import json
import os
import re
import socket
import sys
import time
import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from datetime import datetime
from requests.exceptions import RequestException, ConnectionError, Timeout
from urllib.parse import urlparse

# Initialize colorama
init(autoreset=True)

# Version
VERSION = "1.0.0"

# User-Agent for requests
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

# Banner
BANNER = f"""
{Fore.CYAN}███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ 
{Fore.CYAN}██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
{Fore.CYAN}█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
{Fore.CYAN}██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
{Fore.CYAN}██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
{Fore.CYAN}╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Fore.YELLOW}                                                                            v{VERSION}
{Fore.GREEN}[+] OSINT Tool for Username Reconnaissance, Domain Information, and Social Media Profiling
"""

# Social media and websites to check for username
SITES = {
    "Instagram": {
        "url": "https://www.instagram.com/{}/",
        "error_type": "response_code",
        "error_value": 404
    },
    "Twitter/X": {
        "url": "https://twitter.com/{}",
        "error_type": "message",
        "error_value": "This account doesn't exist"
    },
    "Facebook": {
        "url": "https://www.facebook.com/{}",
        "error_type": "response_code",
        "error_value": 404
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{}",
        "error_type": "message",
        "error_value": "Couldn't find this account"
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{}",
        "error_type": "message",
        "error_value": "404 Not Found"
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{}",
        "error_type": "response_code",
        "error_value": 404
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}",
        "error_type": "response_code",
        "error_value": 404
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{}/",
        "error_type": "response_code",
        "error_value": 404
    },
    "GitHub": {
        "url": "https://github.com/{}",
        "error_type": "response_code",
        "error_value": 404
    },
    "Tumblr": {
        "url": "https://{}.tumblr.com",
        "error_type": "response_code",
        "error_value": 404
    },
    "Medium": {
        "url": "https://medium.com/@{}",
        "error_type": "response_code",
        "error_value": 404
    },
    "Quora": {
        "url": "https://www.quora.com/profile/{}",
        "error_type": "response_code",
        "error_value": 404
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{}",
        "error_type": "message",
        "error_value": "Sorry. Unless you've got a time machine, that content is unavailable."
    }
}

class FinderBuster:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.results = {}
        self.output_dir = "finderbuster_results"
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def print_banner(self):
        """Print the banner of the tool."""
        print(BANNER)
    
    def save_results(self, filename):
        """Save results to a JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.output_dir, f"{filename}_{timestamp}.json")
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        print(f"{Fore.GREEN}[+] Results saved to {filepath}")
        return filepath
    
    def check_username(self, username):
        """Check username across various social media platforms."""
        print(f"\n{Fore.YELLOW}[*] Looking for username '{username}' across {len(SITES)} platforms...")
        self.results["username_search"] = {"input": username, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "results": {}}
        
        # Use ThreadPoolExecutor to check sites concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_site = {
                executor.submit(self.check_site, site_name, site_info, username): site_name
                for site_name, site_info in SITES.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_site):
                site_name = future_to_site[future]
                try:
                    exists, profile_url, message = future.result()
                    
                    if exists:
                        print(f"{Fore.GREEN}[+] {site_name}: {profile_url} - {message}")
                    else:
                        print(f"{Fore.RED}[-] {site_name}: {message}")
                    
                    self.results["username_search"]["results"][site_name] = {
                        "exists": exists,
                        "url": profile_url,
                        "message": message
                    }
                    
                except Exception as e:
                    print(f"{Fore.RED}[!] Error checking {site_name}: {str(e)}")
                    self.results["username_search"]["results"][site_name] = {
                        "exists": False,
                        "url": SITES[site_name]["url"].format(username),
                        "message": f"Error: {str(e)}"
                    }
        
        # Summary
        found_count = sum(1 for site in self.results["username_search"]["results"].values() if site["exists"])
        print(f"\n{Fore.YELLOW}[*] Username search complete. Found on {found_count} out of {len(SITES)} platforms.")
        
        return self.results["username_search"]
    
    def check_site(self, site_name, site_info, username):
        """Check if username exists on a specific site."""
        url = site_info["url"].format(username)
        error_type = site_info["error_type"]
        error_value = site_info["error_value"]
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            if error_type == "response_code":
                if response.status_code != error_value:
                    return True, url, "Profile exists"
                else:
                    return False, url, "Profile not found"
            
            elif error_type == "message":
                if error_value not in response.text:
                    return True, url, "Profile exists"
                else:
                    return False, url, "Profile not found"
            
        except ConnectionError:
            return False, url, "Connection error"
        except Timeout:
            return False, url, "Request timed out"
        except RequestException as e:
            return False, url, f"Request error: {str(e)}"
    
    def get_domain_info(self, domain):
        """Gather extensive domain information including WHOIS, DNS, and server details."""
        print(f"\n{Fore.YELLOW}[*] Gathering information for domain '{domain}'...")
        self.results["domain_info"] = {"input": domain, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "results": {}}
        
        # Validate domain format
        if not self._is_valid_domain(domain):
            print(f"{Fore.RED}[!] Invalid domain format: {domain}")
            self.results["domain_info"]["results"]["error"] = "Invalid domain format"
            return self.results["domain_info"]
        
        # Get WHOIS information
        try:
            print(f"{Fore.CYAN}[*] Fetching WHOIS information...")
            whois_info = whois.whois(domain)
            self.results["domain_info"]["results"]["whois"] = {
                "registrar": whois_info.registrar,
                "creation_date": str(whois_info.creation_date) if whois_info.creation_date else None,
                "expiration_date": str(whois_info.expiration_date) if whois_info.expiration_date else None,
                "updated_date": str(whois_info.updated_date) if whois_info.updated_date else None,
                "name_servers": whois_info.name_servers,
                "status": whois_info.status,
                "emails": whois_info.emails,
                "country": whois_info.country,
                "org": whois_info.org
            }
            
            print(f"{Fore.GREEN}[+] WHOIS: Registrar: {whois_info.registrar}")
            print(f"{Fore.GREEN}[+] WHOIS: Creation Date: {whois_info.creation_date}")
            print(f"{Fore.GREEN}[+] WHOIS: Expiration Date: {whois_info.expiration_date}")
            if whois_info.name_servers:
                print(f"{Fore.GREEN}[+] WHOIS: Name Servers: {', '.join(whois_info.name_servers) if isinstance(whois_info.name_servers, list) else whois_info.name_servers}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error fetching WHOIS information: {str(e)}")
            self.results["domain_info"]["results"]["whois"] = {"error": str(e)}
        
        # Get DNS Records
        print(f"{Fore.CYAN}[*] Fetching DNS records...")
        self.results["domain_info"]["results"]["dns"] = {}
        
        for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records = [str(answer) for answer in answers]
                self.results["domain_info"]["results"]["dns"][record_type] = records
                
                print(f"{Fore.GREEN}[+] DNS {record_type} Records: {', '.join(records)}")
            
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                self.results["domain_info"]["results"]["dns"][record_type] = []
                print(f"{Fore.YELLOW}[-] No {record_type} records found")
            
            except Exception as e:
                self.results["domain_info"]["results"]["dns"][record_type] = {"error": str(e)}
                print(f"{Fore.RED}[!] Error fetching {record_type} records: {str(e)}")
        
        # Get IP Information
        try:
            print(f"{Fore.CYAN}[*] Fetching IP information...")
            ip = socket.gethostbyname(domain)
            self.results["domain_info"]["results"]["ip"] = {"address": ip}
            
            print(f"{Fore.GREEN}[+] IP Address: {ip}")
            
            # Get IP geolocation (optional)
            try:
                geo_response = self.session.get(f"https://ipinfo.io/{ip}/json", timeout=10)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    self.results["domain_info"]["results"]["ip"]["geolocation"] = geo_data
                    
                    print(f"{Fore.GREEN}[+] IP Location: {geo_data.get('city', 'N/A')}, {geo_data.get('region', 'N/A')}, {geo_data.get('country', 'N/A')}")
                    print(f"{Fore.GREEN}[+] IP Organization: {geo_data.get('org', 'N/A')}")
            
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Could not fetch IP geolocation: {str(e)}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error resolving IP: {str(e)}")
            self.results["domain_info"]["results"]["ip"] = {"error": str(e)}
        
        # Get HTTP Server Information
        try:
            print(f"{Fore.CYAN}[*] Fetching HTTP server information...")
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            self.results["domain_info"]["results"]["http"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "final_url": response.url
            }
            
            print(f"{Fore.GREEN}[+] HTTP Status: {response.status_code}")
            print(f"{Fore.GREEN}[+] Server: {response.headers.get('Server', 'N/A')}")
            print(f"{Fore.GREEN}[+] X-Powered-By: {response.headers.get('X-Powered-By', 'N/A')}")
            
            # Check for redirects
            if response.history:
                redirects = [h.url for h in response.history]
                self.results["domain_info"]["results"]["http"]["redirects"] = redirects
                print(f"{Fore.GREEN}[+] Redirects: {' -> '.join(redirects)} -> {response.url}")
        
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            try:
                url = f"http://{domain}"
                response = requests.get(url, timeout=10, allow_redirects=True)
                
                self.results["domain_info"]["results"]["http"] = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "final_url": response.url
                }
                
                print(f"{Fore.GREEN}[+] HTTP Status: {response.status_code}")
                print(f"{Fore.GREEN}[+] Server: {response.headers.get('Server', 'N/A')}")
            
            except Exception as e:
                print(f"{Fore.RED}[!] Error fetching HTTP information: {str(e)}")
                self.results["domain_info"]["results"]["http"] = {"error": str(e)}
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error fetching HTTP information: {str(e)}")
            self.results["domain_info"]["results"]["http"] = {"error": str(e)}
        
        print(f"\n{Fore.YELLOW}[*] Domain information gathering complete for {domain}")
        return self.results["domain_info"]
    
    def get_social_media_profile(self, platform, identifier):
        """Extract profile information from social media platforms."""
        print(f"\n{Fore.YELLOW}[*] Extracting profile information from {platform} for '{identifier}'...")
        self.results["social_profile"] = {"platform": platform, "identifier": identifier, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "results": {}}
        
        if platform.lower() == "instagram":
            return self._get_instagram_profile(identifier)
        elif platform.lower() == "twitter" or platform.lower() == "x":
            return self._get_twitter_profile(identifier)
        elif platform.lower() == "github":
            return self._get_github_profile(identifier)
        elif platform.lower() == "linkedin":
            return self._get_linkedin_profile(identifier)
        else:
            print(f"{Fore.RED}[!] Unsupported platform: {platform}")
            print(f"{Fore.YELLOW}[*] Supported platforms: instagram, twitter, github, linkedin")
            self.results["social_profile"]["results"]["error"] = f"Unsupported platform: {platform}"
            return self.results["social_profile"]
    
    def _get_instagram_profile(self, username):
        """Extract profile information from Instagram."""
        try:
            url = f"https://www.instagram.com/{username}/"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 404:
                print(f"{Fore.RED}[-] Instagram profile not found: {username}")
                self.results["social_profile"]["results"]["error"] = "Profile not found"
                return self.results["social_profile"]
            
            # Try to extract profile information from the HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for the JSON data in the page
            script_tag = soup.find('script', string=re.compile('window._sharedData'))
            if script_tag:
                json_text = script_tag.string.split('window._sharedData = ')[1][:-1]
                data = json.loads(json_text)
                
                if 'entry_data' in data and 'ProfilePage' in data['entry_data']:
                    profile = data['entry_data']['ProfilePage'][0]['graphql']['user']
                    
                    self.results["social_profile"]["results"] = {
                        "username": profile.get('username'),
                        "full_name": profile.get('full_name'),
                        "biography": profile.get('biography'),
                        "followers": profile.get('edge_followed_by', {}).get('count'),
                        "following": profile.get('edge_follow', {}).get('count'),
                        "posts_count": profile.get('edge_owner_to_timeline_media', {}).get('count'),
                        "is_private": profile.get('is_private'),
                        "is_verified": profile.get('is_verified'),
                        "profile_pic_url": profile.get('profile_pic_url_hd'),
                        "external_url": profile.get('external_url')
                    }
                    
                    print(f"{Fore.GREEN}[+] Username: {profile.get('username')}")
                    print(f"{Fore.GREEN}[+] Full Name: {profile.get('full_name')}")
                    print(f"{Fore.GREEN}[+] Biography: {profile.get('biography')}")
                    print(f"{Fore.GREEN}[+] Followers: {profile.get('edge_followed_by', {}).get('count')}")
                    print(f"{Fore.GREEN}[+] Following: {profile.get('edge_follow', {}).get('count')}")
                    print(f"{Fore.GREEN}[+] Posts: {profile.get('edge_owner_to_timeline_media', {}).get('count')}")
                    print(f"{Fore.GREEN}[+] Private: {profile.get('is_private')}")
                    print(f"{Fore.GREEN}[+] Verified: {profile.get('is_verified')}")
                    print(f"{Fore.GREEN}[+] External URL: {profile.get('external_url')}")
                    
                    return self.results["social_profile"]
            
            # Fallback method using meta tags
            meta_properties = {
                "og:title": "title",
                "og:description": "description",
                "og:image": "profile_pic_url"
            }
            
            for prop, key in meta_properties.items():
                meta_tag = soup.find('meta', property=prop)
                if meta_tag:
                    self.results["social_profile"]["results"][key] = meta_tag.get('content')
            
            if self.results["social_profile"]["results"]:
                for key, value in self.results["social_profile"]["results"].items():
                    print(f"{Fore.GREEN}[+] {key}: {value}")
                
                self.results["social_profile"]["results"]["profile_url"] = url
                self.results["social_profile"]["results"]["note"] = "Limited data extracted due to Instagram restrictions"
                return self.results["social_profile"]
            
            print(f"{Fore.YELLOW}[-] Could not extract detailed profile information from Instagram")
            self.results["social_profile"]["results"]["error"] = "Could not extract profile information"
            self.results["social_profile"]["results"]["profile_url"] = url
            self.results["social_profile"]["results"]["exists"] = response.status_code == 200
            
            return self.results["social_profile"]
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting Instagram profile: {str(e)}")
            self.results["social_profile"]["results"]["error"] = str(e)
            return self.results["social_profile"]
    
    def _get_twitter_profile(self, username):
        """Extract profile information from Twitter/X."""
        try:
            url = f"https://twitter.com/{username}"
            response = self.session.get(url, timeout=10)
            
            if "This account doesn't exist" in response.text:
                print(f"{Fore.RED}[-] Twitter/X profile not found: {username}")
                self.results["social_profile"]["results"]["error"] = "Profile not found"
                return self.results["social_profile"]
            
            # Try to extract profile information from the HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract meta information
            meta_properties = {
                "og:title": "title",
                "og:description": "description",
                "og:image": "profile_pic_url"
            }
            
            for prop, key in meta_properties.items():
                meta_tag = soup.find('meta', property=prop)
                if meta_tag:
                    self.results["social_profile"]["results"][key] = meta_tag.get('content')
            
            if "title" in self.results["social_profile"]["results"]:
                title = self.results["social_profile"]["results"]["title"]
                self.results["social_profile"]["results"]["full_name"] = title.split("(")[0].strip() if "(" in title else title
                
                if "(" in title and ")" in title:
                    self.results["social_profile"]["results"]["username"] = title.split("(")[1].split(")")[0].strip("@")
            
            if "description" in self.results["social_profile"]["results"]:
                self.results["social_profile"]["results"]["bio"] = self.results["social_profile"]["results"]["description"]
            
            # Add profile URL
            self.results["social_profile"]["results"]["profile_url"] = url
            self.results["social_profile"]["results"]["exists"] = True
            self.results["social_profile"]["results"]["note"] = "Limited data extracted due to Twitter/X API restrictions"
            
            for key, value in self.results["social_profile"]["results"].items():
                print(f"{Fore.GREEN}[+] {key}: {value}")
            
            return self.results["social_profile"]
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting Twitter/X profile: {str(e)}")
            self.results["social_profile"]["results"]["error"] = str(e)
            return self.results["social_profile"]
    
    def _get_github_profile(self, username):
        """Extract profile information from GitHub."""
        try:
            url = f"https://github.com/{username}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 404:
                print(f"{Fore.RED}[-] GitHub profile not found: {username}")
                self.results["social_profile"]["results"]["error"] = "Profile not found"
                return self.results["social_profile"]
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract profile information
            profile_info = {
                "username": username,
                "profile_url": url,
                "exists": True
            }
            
            # Full name
            name_element = soup.find("span", {"itemprop": "name"})
            if name_element:
                profile_info["full_name"] = name_element.text.strip()
            
            # Bio
            bio_element = soup.find("div", {"class": "p-note"}) or soup.find("div", {"class": "user-profile-bio"})
            if bio_element:
                profile_info["bio"] = bio_element.text.strip()
            
            # Location
            location_element = soup.find("li", {"itemprop": "homeLocation"})
            if location_element:
                profile_info["location"] = location_element.text.strip()
            
            # Company
            company_element = soup.find("li", {"itemprop": "worksFor"})
            if company_element:
                profile_info["company"] = company_element.text.strip()
            
            # Website
            website_element = soup.find("li", {"itemprop": "url"})
            if website_element:
                profile_info["website"] = website_element.find("a").get("href")
            
            # Twitter/X link
            twitter_element = soup.find("li", {"itemprop": "social"})
            if twitter_element and "twitter" in str(twitter_element).lower():
                profile_info["twitter"] = twitter_element.find("a").text.strip()
            
            # Followers and following
            followers_element = soup.find("span", {"class": "text-bold"}, string=re.compile(r"followers|Followers"))
            if followers_element:
                profile_info["followers"] = followers_element.text.strip()
            
            following_element = soup.find("span", {"class": "text-bold"}, string=re.compile(r"following|Following"))
            if following_element:
                profile_info["following"] = following_element.text.strip()
            
            # Repositories
            repo_counter = soup.find("span", string=re.compile(r"Repositories"))
            if repo_counter:
                repo_number = repo_counter.find_previous("span", {"class": "Counter"})
                if repo_number:
                    profile_info["repositories"] = repo_number.text.strip()
            
            # Contributions
            contributions_element = soup.find("h2", string=re.compile(r"contributions"))
            if contributions_element:
                contributions_text = contributions_element.text.strip()
                match = re.search(r"(\d+) contributions", contributions_text)
                if match:
                    profile_info["contributions"] = match.group(1)
            
            self.results["social_profile"]["results"] = profile_info
            
            # Print results
            for key, value in profile_info.items():
                print(f"{Fore.GREEN}[+] {key}: {value}")
            
            return self.results["social_profile"]
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting GitHub profile: {str(e)}")
            self.results["social_profile"]["results"]["error"] = str(e)
            return self.results["social_profile"]
    
    def _get_linkedin_profile(self, profile_id):
        """Extract basic profile information from LinkedIn."""
        try:
            url = f"https://www.linkedin.com/in/{profile_id}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 404:
                print(f"{Fore.RED}[-] LinkedIn profile not found: {profile_id}")
                self.results["social_profile"]["results"]["error"] = "Profile not found"
                return self.results["social_profile"]
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # LinkedIn heavily protects profile data, so we can only extract meta information
            meta_properties = {
                "og:title": "title",
                "og:description": "description",
                "og:image": "profile_pic_url"
            }
            
            profile_info = {
                "profile_id": profile_id,
                "profile_url": url,
                "exists": response.status_code == 200
            }
            
            for prop, key in meta_properties.items():
                meta_tag = soup.find('meta', property=prop)
                if meta_tag:
                    profile_info[key] = meta_tag.get('content')
            
            # Try to extract name and headline
            if "title" in profile_info:
                title_parts = profile_info["title"].split(" | ")
                if len(title_parts) >= 2:
                    profile_info["full_name"] = title_parts[0]
                    profile_info["headline"] = title_parts[1]
            
            # Add note about limitations
            profile_info["note"] = "Limited data extracted due to LinkedIn restrictions. Full profile data requires authentication."
            
            self.results["social_profile"]["results"] = profile_info
            
            # Print results
            for key, value in profile_info.items():
                print(f"{Fore.GREEN}[+] {key}: {value}")
            
            return self.results["social_profile"]
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting LinkedIn profile: {str(e)}")
            self.results["social_profile"]["results"]["error"] = str(e)
            return self.results["social_profile"]

    def _is_valid_domain(self, domain):
        """Check if a domain has a valid format."""
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))

    # The main() function should be outside the FinderBuster class
    def main():
        """Main function to run the tool."""
        parser = argparse.ArgumentParser(description="FinderBuster - OSINT Tool for Username Reconnaissance, Domain Information, and Social Media Profiling")
        
        # Create subparsers for different functions
        subparsers = parser.add_subparsers(dest="command", help="Command to run")
        
        # Username Search Parser
        username_parser = subparsers.add_parser("username", help="Search for username across different platforms")
        username_parser.add_argument("username", help="Username to search for")
        
        # Domain Info Parser
        domain_parser = subparsers.add_parser("domain", help="Gather information about a domain")
        domain_parser.add_argument("domain", help="Domain to gather information about")
        
        # Social Media Profile Parser
        social_parser = subparsers.add_parser("social", help="Extract profile information from social media platforms")
        social_parser.add_argument("platform", choices=["instagram", "twitter", "x", "github", "linkedin"], 
                                help="Social media platform")
        social_parser.add_argument("identifier", help="Username or profile identifier")
        
        # Version argument
        parser.add_argument("--version", action="version", version=f"FinderBuster v{VERSION}")
        
        args = parser.parse_args()
        
        # Create FinderBuster instance
        finder = FinderBuster()
        finder.print_banner()
        
        if args.command == "username":
            results = finder.check_username(args.username)
            finder.save_results(f"username_{args.username}")
        
        elif args.command == "domain":
            results = finder.get_domain_info(args.domain)
            finder.save_results(f"domain_{args.domain}")
        
        elif args.command == "social":
            results = finder.get_social_media_profile(args.platform, args.identifier)
            finder.save_results(f"social_{args.platform}_{args.identifier}")
        
        else:
            parser.print_help()
            sys.exit(1)
# The main() function should be outside the FinderBuster class
def main():
    """Main function to run the tool."""
    parser = argparse.ArgumentParser(description="FinderBuster - OSINT Tool for Username Reconnaissance, Domain Information, and Social Media Profiling | Created By NunoGans")
    
    # Create subparsers for different functions
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Username Search Parser
    username_parser = subparsers.add_parser("username", help="Search for username across different platforms")
    username_parser.add_argument("username", help="Username to search for")
    
    # Domain Info Parser
    domain_parser = subparsers.add_parser("domain", help="Gather information about a domain")
    domain_parser.add_argument("domain", help="Domain to gather information about")
    
    # Social Media Profile Parser
    social_parser = subparsers.add_parser("social", help="Extract profile information from social media platforms")
    social_parser.add_argument("platform", choices=["instagram", "twitter", "x", "github", "linkedin"], 
                            help="Social media platform")
    social_parser.add_argument("identifier", help="Username or profile identifier")
    
    # Version argument
    parser.add_argument("--version", action="version", version=f"FinderBuster v{VERSION}")
    
    args = parser.parse_args()
    
    # Create FinderBuster instance
    finder = FinderBuster()
    finder.print_banner()
    
    if args.command == "username":
        results = finder.check_username(args.username)
        finder.save_results(f"username_{args.username}")
    
    elif args.command == "domain":
        results = finder.get_domain_info(args.domain)
        finder.save_results(f"domain_{args.domain}")
    
    elif args.command == "social":
        results = finder.get_social_media_profile(args.platform, args.identifier)
        finder.save_results(f"social_{args.platform}_{args.identifier}")
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Process interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred: {str(e)}")
        sys.exit(1)