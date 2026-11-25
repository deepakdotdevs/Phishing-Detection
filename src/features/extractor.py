"""Live URL Feature Extractor for Phishing Website Detection.
Extracts the 30 structural, lexical, network, and DOM features defined in the UCI dataset.
"""
import os
import re
import socket
import ssl
from urllib.parse import urlparse
import requests

FEATURE_COLUMNS = [
    'having_IP_Address',
    'URL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'Domain_registeration_length',
    'Favicon',
    'port',
    'HTTPS_token',
    'Request_URL',
    'URL_of_Anchor',
    'Links_in_tags',
    'SFH',
    'Submitting_to_email',
    'Abnormal_URL',
    'Redirect',
    'on_mouseover',
    'RightClick',
    'popUpWidnow',
    'Iframe',
    'age_of_domain',
    'DNSRecord',
    'web_traffic',
    'Page_Rank',
    'Google_Index',
    'Links_pointing_to_page',
    'Statistical_report'
]

KNOWN_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bitly.com', 'cutt.ly', 'rb.gy', 'shorte.st', 'tiny.cc', 'bl.ink'
}

POPULAR_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'yahoo.com', 'reddit.com', 'netflix.com', 'linkedin.com', 'instagram.com',
    'twitter.com', 'x.com', 'microsoft.com', 'apple.com', 'paypal.com',
    'github.com', 'openai.com', 'bing.com', 'live.com', 'office.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'ebay.com'
}


def extract_features_from_url(url: str, fetch_dom: bool = True, timeout: float = 3.0) -> dict:
    """
    Extract 30 UCI features from a live URL string.
    Returns a dictionary of feature_name -> int value (-1, 0, 1).
    """
    # Ensure scheme
    raw_url = url.strip()
    if not re.match(r'^https?://', raw_url, re.IGNORECASE):
        raw_url = 'http://' + raw_url

    parsed = urlparse(raw_url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    scheme = parsed.scheme.lower()
    full_url = raw_url

    feats = {}

    # 1. having_IP_Address: IP used instead of domain
    # IPv4 regex or hex
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    hex_pattern = r'^0x[0-9a-fA-F]+'
    if re.match(ip_pattern, hostname) or re.match(hex_pattern, hostname) or ':' in hostname:
        feats['having_IP_Address'] = 1
    else:
        feats['having_IP_Address'] = -1

    # 2. URL_Length: <54 -> -1, 54-75 -> 0, >75 -> 1
    url_len = len(full_url)
    if url_len < 54:
        feats['URL_Length'] = -1
    elif url_len <= 75:
        feats['URL_Length'] = 0
    else:
        feats['URL_Length'] = 1

    # 3. Shortining_Service
    domain_lower = hostname.lower()
    if any(s in domain_lower for s in KNOWN_SHORTENERS):
        feats['Shortining_Service'] = 1
    else:
        feats['Shortining_Service'] = -1

    # 4. having_At_Symbol
    feats['having_At_Symbol'] = 1 if '@' in full_url else -1

    # 5. double_slash_redirecting: // after position 7
    last_double_slash = full_url.rfind('//')
    feats['double_slash_redirecting'] = 1 if last_double_slash > 7 else -1

    # 6. Prefix_Suffix: Hyphen in domain
    feats['Prefix_Suffix'] = 1 if '-' in hostname else -1

    # 7. having_Sub_Domain: count dots excluding www
    clean_host = re.sub(r'^www\.', '', domain_lower)
    dots = clean_host.count('.')
    if feats['having_IP_Address'] == 1:
        feats['having_Sub_Domain'] = 1
    elif dots <= 1:
        feats['having_Sub_Domain'] = -1
    elif dots == 2:
        feats['having_Sub_Domain'] = 0
    else:
        feats['having_Sub_Domain'] = 1

    # 8. SSLfinal_State
    ssl_valid = False
    if scheme != 'https':
        feats['SSLfinal_State'] = 1  # No SSL
    else:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        ssl_valid = True
            feats['SSLfinal_State'] = -1 if ssl_valid else 0
        except Exception:
            feats['SSLfinal_State'] = 1  # Untrusted or broken SSL

    # 11. port: non-standard port in URL
    if parsed.port and parsed.port not in (80, 443):
        feats['port'] = 1
    else:
        feats['port'] = -1

    # 12. HTTPS_token: 'https' or 'http' inside domain part
    host_without_tld = '.'.join(clean_host.split('.')[:-1])
    if 'https' in host_without_tld or 'http' in host_without_tld:
        feats['HTTPS_token'] = 1
    else:
        feats['HTTPS_token'] = -1

    # 25. DNSRecord: test DNS resolution
    dns_resolved = False
    try:
        socket.gethostbyname(hostname)
        dns_resolved = True
        feats['DNSRecord'] = 1  # Valid DNS in UCI dataset = 1
    except Exception:
        feats['DNSRecord'] = -1  # No DNS record

    # Check if popular domain for external rank features
    is_popular = any(clean_host == pop or clean_host.endswith('.' + pop) for pop in POPULAR_DOMAINS)

    if feats['having_IP_Address'] == 1:
        feats['DNSRecord'] = -1
        feats['web_traffic'] = 1
        feats['Page_Rank'] = 1
        feats['Google_Index'] = -1
        feats['Links_pointing_to_page'] = 1
        feats['age_of_domain'] = 1
        feats['Domain_registeration_length'] = 1
        feats['Abnormal_URL'] = 1
        feats['Statistical_report'] = 1
        feats['URL_of_Anchor'] = 1
        feats['SFH'] = 1
    elif is_popular:
        feats['web_traffic'] = -1
        feats['Page_Rank'] = -1
        feats['Google_Index'] = 1
        feats['Links_pointing_to_page'] = -1
        feats['age_of_domain'] = -1
        feats['Domain_registeration_length'] = -1
        feats['Abnormal_URL'] = -1
        feats['Statistical_report'] = -1
    else:
        feats['web_traffic'] = 1 if not dns_resolved else 0
        feats['Page_Rank'] = 1
        feats['Google_Index'] = 1
        feats['Links_pointing_to_page'] = 1
        feats['age_of_domain'] = 1 if not dns_resolved else -1
        feats['Domain_registeration_length'] = 1
        feats['Abnormal_URL'] = 1 if not dns_resolved else -1
        feats['Statistical_report'] = 1 if not dns_resolved else -1

    # Defaults for DOM features if network fetch is skipped or fails
    feats['Favicon'] = -1
    feats['Request_URL'] = -1
    feats['URL_of_Anchor'] = 1 if not dns_resolved else -1
    feats['Links_in_tags'] = -1
    feats['SFH'] = -1
    feats['Submitting_to_email'] = -1
    feats['Redirect'] = -1
    feats['on_mouseover'] = -1
    feats['RightClick'] = -1
    feats['popUpWidnow'] = -1
    feats['Iframe'] = -1

    # Optional live DOM extraction
    if fetch_dom and dns_resolved:
        try:
            resp = requests.get(
                full_url,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
                allow_redirects=True
            )
            # 19. Redirect
            redirects_count = len(resp.history)
            if redirects_count <= 1:
                feats['Redirect'] = -1
            elif redirects_count <= 3:
                feats['Redirect'] = 0
            else:
                feats['Redirect'] = 1

            html = resp.text.lower()

            # 14. URL_of_Anchor
            anchors = re.findall(r'<a\s+[^>]*href=["\'](.*?)["\']', html)
            if anchors:
                suspicious_anchors = 0
                for a in anchors:
                    a = a.strip()
                    if a in ('#', '', 'javascript:void(0)', 'javascript:void(0);', 'javascript:;'):
                        suspicious_anchors += 1
                    elif re.match(r'^https?://', a) and hostname not in a:
                        suspicious_anchors += 1
                ratio = suspicious_anchors / len(anchors)
                if ratio < 0.31:
                    feats['URL_of_Anchor'] = -1
                elif ratio <= 0.67:
                    feats['URL_of_Anchor'] = 0
                else:
                    feats['URL_of_Anchor'] = 1

            # 13. Request_URL: external images/media
            imgs = re.findall(r'<img\s+[^>]*src=["\'](.*?)["\']', html)
            if imgs:
                ext_imgs = sum(1 for img in imgs if re.match(r'^https?://', img) and hostname not in img)
                ratio_img = ext_imgs / len(imgs)
                if ratio_img < 0.22:
                    feats['Request_URL'] = -1
                elif ratio_img <= 0.61:
                    feats['Request_URL'] = 0
                else:
                    feats['Request_URL'] = 1

            # 15. Links_in_tags
            meta_links = re.findall(r'<(?:meta|script|link)\s+[^>]*(?:src|href)=["\'](.*?)["\']', html)
            if meta_links:
                ext_meta = sum(1 for l in meta_links if re.match(r'^https?://', l) and hostname not in l)
                ratio_meta = ext_meta / len(meta_links)
                if ratio_meta < 0.17:
                    feats['Links_in_tags'] = -1
                elif ratio_meta <= 0.81:
                    feats['Links_in_tags'] = 0
                else:
                    feats['Links_in_tags'] = 1

            # 16. SFH: Server Form Handler
            forms = re.findall(r'<form\s+[^>]*action=["\'](.*?)["\']', html)
            for action in forms:
                action = action.strip()
                if action in ('', 'about:blank'):
                    feats['SFH'] = 1
                elif re.match(r'^https?://', action) and hostname not in action:
                    feats['SFH'] = 0

            # 17. Submitting_to_email
            if 'mailto:' in html or 'mailto' in html:
                feats['Submitting_to_email'] = 1

            # 20. on_mouseover
            if 'onmouseover' in html and 'status' in html:
                feats['on_mouseover'] = 1

            # 21. RightClick
            if 'contextmenu' in html and ('preventdefault' in html or 'event.button==2' in html):
                feats['RightClick'] = 1

            # 22. popUpWidnow
            if 'prompt(' in html or ('window.open' in html and 'input' in html):
                feats['popUpWidnow'] = 1

            # 23. Iframe
            if '<iframe' in html and ('display:none' in html or 'visibility:hidden' in html or 'width="0"' in html):
                feats['Iframe'] = 1

        except Exception:
            # Network fetch timed out or connection refused: retain existing heuristic defaults
            pass

    return feats
