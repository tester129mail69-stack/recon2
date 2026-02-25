"""Technology fingerprinting for GODRECON.

Built-in fingerprint rules embedded directly — no external fingerprints.json needed.
Covers 50+ technologies: web servers, CMS, frameworks, JS libs, WAFs, CDNs, DevOps.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_BUILTIN_FINGERPRINTS: List[Dict[str, Any]] = [
    # Web Servers
    {"name": "Nginx", "category": "web-server", "website": "https://nginx.org",
     "header_patterns": [r"nginx"], "version_regex": r"nginx[/\s]([\d.]+)",
     "cookie_patterns": [], "body_patterns": [], "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Apache HTTP Server", "category": "web-server", "website": "https://httpd.apache.org",
     "header_patterns": [r"Apache[/\s][\d.]", r"server:\s*apache"], "version_regex": r"Apache[/\s]([\d.]+)",
     "cookie_patterns": [], "body_patterns": [r"Apache/[\d.]+ Server"], "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Microsoft IIS", "category": "web-server", "website": "https://www.iis.net",
     "header_patterns": [r"Microsoft-IIS", r"server:\s*IIS"], "version_regex": r"Microsoft-IIS/([\d.]+)",
     "cookie_patterns": [], "body_patterns": [], "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "LiteSpeed", "category": "web-server", "website": "https://www.litespeedtech.com",
     "header_patterns": [r"LiteSpeed", r"X-Powered-By:\s*LiteSpeed"], "version_regex": r"LiteSpeed/([\d.]+)",
     "cookie_patterns": [], "body_patterns": [], "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "OpenResty", "category": "web-server", "website": "https://openresty.org",
     "header_patterns": [r"openresty"], "version_regex": r"openresty/([\d.]+)",
     "cookie_patterns": [], "body_patterns": [], "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Caddy", "category": "web-server", "website": "https://caddyserver.com",
     "header_patterns": [r"Caddy", r"server:\s*Caddy"], "version_regex": r"Caddy/([\d.]+)",
     "cookie_patterns": [], "body_patterns": [], "meta_patterns": [], "script_patterns": [], "url_patterns": []},

    # Languages / Runtimes
    {"name": "PHP", "category": "language", "website": "https://php.net",
     "header_patterns": [r"X-Powered-By:\s*PHP"], "version_regex": r"PHP/([\d.]+)",
     "cookie_patterns": [r"PHPSESSID"], "body_patterns": [r"<\?php"],
     "meta_patterns": [], "script_patterns": [], "url_patterns": [r"\.php(\?|$)"]},
    {"name": "ASP.NET", "category": "language", "website": "https://dotnet.microsoft.com",
     "header_patterns": [r"X-Powered-By:\s*ASP\.NET", r"X-AspNet-Version"], "version_regex": r"ASP\.NET[_\s]([^;,\s]+)",
     "cookie_patterns": [r"ASP\.NET_SessionId", r"ASPXAUTH"],
     "body_patterns": [r"__VIEWSTATE", r"WebResource\.axd"],
     "meta_patterns": [], "script_patterns": [], "url_patterns": [r"\.(aspx?|ashx|asmx)(\?|$)"]},
    {"name": "Node.js", "category": "language", "website": "https://nodejs.org",
     "header_patterns": [r"X-Powered-By:\s*Express", r"server:\s*Node"], "version_regex": r"node[/\s]v?([\d.]+)",
     "cookie_patterns": [r"connect\.sid"], "body_patterns": [],
     "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Python", "category": "language", "website": "https://python.org",
     "header_patterns": [r"Python/[\d.]+", r"X-Powered-By:\s*Python"], "version_regex": r"Python/([\d.]+)",
     "cookie_patterns": [], "body_patterns": [], "meta_patterns": [], "script_patterns": [], "url_patterns": []},

    # CMS
    {"name": "WordPress", "category": "cms", "website": "https://wordpress.org",
     "header_patterns": [r"X-Pingback.*xmlrpc"], "version_regex": r'content="WordPress ([\d.]+)"',
     "cookie_patterns": [r"wordpress_", r"wp-settings-"],
     "body_patterns": [r"/wp-content/", r"/wp-includes/"],
     "meta_patterns": [r'<meta[^>]+content=["\']WordPress[\s/]([\d.]+)', r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress'],
     "script_patterns": [r"wp-includes/js/", r"wp-content/plugins/"],
     "url_patterns": [r"/wp-admin/", r"/wp-login\.php"]},
    {"name": "Drupal", "category": "cms", "website": "https://drupal.org",
     "header_patterns": [r"X-Generator:\s*Drupal", r"X-Drupal-"], "version_regex": r"Drupal ([\d.]+)",
     "cookie_patterns": [r"SESS[a-f0-9]{32}"],
     "body_patterns": [r"/sites/default/files/", r"/misc/drupal\.js", r"Drupal\.settings"],
     "meta_patterns": [r'<meta[^>]+content=["\']Drupal'],
     "script_patterns": [r"/sites/all/modules/"], "url_patterns": [r"\?q=node/"]},
    {"name": "Joomla", "category": "cms", "website": "https://joomla.org",
     "header_patterns": [], "version_regex": r"Joomla! ([\d.]+)",
     "cookie_patterns": [r"joomla_user_state"],
     "body_patterns": [r"/components/com_", r"Joomla!", r"/media/jui/"],
     "meta_patterns": [r'<meta[^>]+content=["\']Joomla'],
     "script_patterns": [r"/media/system/js/"], "url_patterns": [r"/administrator/index\.php"]},
    {"name": "Magento", "category": "cms", "website": "https://magento.com",
     "header_patterns": [r"X-Magento-"], "version_regex": r"Magento/([\d.]+)",
     "cookie_patterns": [], "body_patterns": [r"skin/frontend/", r"Mage\.", r"/js/mage/"],
     "meta_patterns": [], "script_patterns": [r"mage/", r"Magento_"], "url_patterns": []},
    {"name": "Shopify", "category": "cms", "website": "https://shopify.com",
     "header_patterns": [r"X-ShopId", r"X-Shopify"], "version_regex": None,
     "cookie_patterns": [r"_shopify_"],
     "body_patterns": [r"cdn\.shopify\.com", r"Shopify\.theme"],
     "meta_patterns": [], "script_patterns": [r"cdn\.shopify\.com/s/"], "url_patterns": []},
    {"name": "Ghost", "category": "cms", "website": "https://ghost.org",
     "header_patterns": [r"X-Ghost-Cache"], "version_regex": r"Ghost/([\d.]+)",
     "cookie_patterns": [r"ghost-admin-api-session"],
     "body_patterns": [r"/ghost/api/", r"ghost\.io"],
     "meta_patterns": [r'<meta[^>]+content=["\']Ghost'],
     "script_patterns": [], "url_patterns": [r"/ghost/"]},
    {"name": "TYPO3", "category": "cms", "website": "https://typo3.org",
     "header_patterns": [], "version_regex": r"TYPO3 CMS ([\d.]+)",
     "cookie_patterns": [r"fe_typo_user", r"be_typo_user"],
     "body_patterns": [r"typo3/", r"tx_"],
     "meta_patterns": [r'content=["\']TYPO3'],
     "script_patterns": [r"typo3/sysext/"], "url_patterns": [r"/typo3/"]},

    # Frameworks
    {"name": "Laravel", "category": "framework", "website": "https://laravel.com",
     "header_patterns": [], "version_regex": None,
     "cookie_patterns": [r"laravel_session", r"XSRF-TOKEN"],
     "body_patterns": [r"laravel"], "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Django", "category": "framework", "website": "https://djangoproject.com",
     "header_patterns": [], "version_regex": None,
     "cookie_patterns": [r"csrftoken", r"sessionid"],
     "body_patterns": [r"csrfmiddlewaretoken"],
     "meta_patterns": [], "script_patterns": [r"/static/admin/js/"], "url_patterns": []},
    {"name": "Ruby on Rails", "category": "framework", "website": "https://rubyonrails.org",
     "header_patterns": [r"X-Request-Id", r"X-Runtime"], "version_regex": None,
     "cookie_patterns": [r"_rails_session"],
     "body_patterns": [r"csrf-param.*authenticity_token"],
     "meta_patterns": [r'<meta[^>]+name=["\']csrf-token'],
     "script_patterns": [r"rails\.js"], "url_patterns": []},
    {"name": "Spring Boot", "category": "framework", "website": "https://spring.io",
     "header_patterns": [r"X-Application-Context"], "version_regex": None,
     "cookie_patterns": [r"JSESSIONID"],
     "body_patterns": [r"Whitelabel Error Page", r"Spring Boot"],
     "meta_patterns": [], "script_patterns": [], "url_patterns": [r"/actuator"]},
    {"name": "Flask", "category": "framework", "website": "https://flask.palletsprojects.com",
     "header_patterns": [r"Werkzeug"], "version_regex": r"Werkzeug/([\d.]+)",
     "cookie_patterns": [r"session"],
     "body_patterns": [r"Werkzeug Debugger"],
     "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Express", "category": "framework", "website": "https://expressjs.com",
     "header_patterns": [r"X-Powered-By:\s*Express"], "version_regex": None,
     "cookie_patterns": [], "body_patterns": [], "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Next.js", "category": "framework", "website": "https://nextjs.org",
     "header_patterns": [r"X-Powered-By:\s*Next\.js"], "version_regex": r"Next\.js ([\d.]+)",
     "cookie_patterns": [],
     "body_patterns": [r"__NEXT_DATA__", r"_next/static/"],
     "meta_patterns": [], "script_patterns": [r"/_next/static/chunks/"], "url_patterns": []},
    {"name": "Nuxt.js", "category": "framework", "website": "https://nuxt.com",
     "header_patterns": [r"X-Powered-By:\s*Nuxt"], "version_regex": None,
     "cookie_patterns": [], "body_patterns": [r"__nuxt", r"_nuxt/"],
     "meta_patterns": [], "script_patterns": [r"/_nuxt/"], "url_patterns": []},
    {"name": "FastAPI", "category": "framework", "website": "https://fastapi.tiangolo.com",
     "header_patterns": [], "version_regex": None,
     "cookie_patterns": [], "body_patterns": [r'"openapi"', r"FastAPI"],
     "meta_patterns": [], "script_patterns": [], "url_patterns": [r"/docs", r"/redoc", r"/openapi\.json"]},

    # JavaScript Libraries
    {"name": "jQuery", "category": "javascript-library", "website": "https://jquery.com",
     "header_patterns": [], "version_regex": r'jquery[.-]?([\d.]+)\.(?:min\.)?js',
     "cookie_patterns": [],
     "body_patterns": [r"jquery[\.-][\d.]+\.(?:min\.)?js"],
     "meta_patterns": [], "script_patterns": [r'src=["\'][^"\']*jquery'], "url_patterns": []},
    {"name": "React", "category": "javascript-library", "website": "https://react.dev",
     "header_patterns": [], "version_regex": None,
     "cookie_patterns": [],
     "body_patterns": [r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"react\.development\.js"],
     "meta_patterns": [], "script_patterns": [r"react\.(?:development|production)\.min\.js"], "url_patterns": []},
    {"name": "Angular", "category": "javascript-library", "website": "https://angular.io",
     "header_patterns": [], "version_regex": r'@angular/core@([\d.]+)',
     "cookie_patterns": [],
     "body_patterns": [r"ng-version=", r"angular\.min\.js"],
     "meta_patterns": [], "script_patterns": [r"angular\.min\.js"], "url_patterns": []},
    {"name": "Vue.js", "category": "javascript-library", "website": "https://vuejs.org",
     "header_patterns": [], "version_regex": r'vue[/\s@]([0-9]+\.[0-9]+)',
     "cookie_patterns": [],
     "body_patterns": [r'data-v-[a-f0-9]+', r"Vue\.config"],
     "meta_patterns": [], "script_patterns": [r"vue\.(?:min\.)?js"], "url_patterns": []},
    {"name": "Bootstrap", "category": "css-framework", "website": "https://getbootstrap.com",
     "header_patterns": [], "version_regex": r'bootstrap[/\s@-]([\d.]+)',
     "cookie_patterns": [],
     "body_patterns": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
     "meta_patterns": [], "script_patterns": [r"bootstrap\.(?:min\.)?js"], "url_patterns": []},

    # WAF
    {"name": "Cloudflare WAF", "category": "waf", "website": "https://cloudflare.com",
     "header_patterns": [r"server:\s*cloudflare", r"cf-ray"], "version_regex": None,
     "cookie_patterns": [r"__cflb", r"cf_clearance"],
     "body_patterns": [r"cloudflare", r"cf-browser-verification"],
     "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Imperva Incapsula", "category": "waf", "website": "https://imperva.com",
     "header_patterns": [r"X-Iinfo", r"X-CDN:\s*Incapsula"], "version_regex": None,
     "cookie_patterns": [r"incap_ses", r"visid_incap"],
     "body_patterns": [r"incapsula", r"/_Incapsula_Resource"],
     "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Sucuri WAF", "category": "waf", "website": "https://sucuri.net",
     "header_patterns": [r"X-Sucuri-ID", r"server:\s*Sucuri"], "version_regex": None,
     "cookie_patterns": [], "body_patterns": [r"Sucuri WebSite Firewall"],
     "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "ModSecurity", "category": "waf", "website": "https://modsecurity.org",
     "header_patterns": [r"X-Mod-Security", r"Mod_Security"], "version_regex": None,
     "cookie_patterns": [], "body_patterns": [r"ModSecurity", r"This error was generated by Mod_Security"],
     "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "AWS WAF", "category": "waf", "website": "https://aws.amazon.com/waf/",
     "header_patterns": [r"x-amzn-requestid", r"x-amz-cf-id"], "version_regex": None,
     "cookie_patterns": [r"aws-waf-token"], "body_patterns": [],
     "meta_patterns": [], "script_patterns": [], "url_patterns": []},

    # CDN
    {"name": "Cloudflare CDN", "category": "cdn", "website": "https://cloudflare.com",
     "header_patterns": [r"cf-cache-status"], "version_regex": None,
     "cookie_patterns": [r"__cflb"], "body_patterns": [],
     "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "AWS CloudFront", "category": "cdn", "website": "https://aws.amazon.com/cloudfront/",
     "header_patterns": [r"X-Amz-Cf-Id", r"Via:.*cloudfront"], "version_regex": None,
     "cookie_patterns": [], "body_patterns": [], "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Fastly", "category": "cdn", "website": "https://fastly.com",
     "header_patterns": [r"X-Served-By.*cache-", r"Fastly-Debug-Digest"], "version_regex": None,
     "cookie_patterns": [], "body_patterns": [], "meta_patterns": [], "script_patterns": [], "url_patterns": []},
    {"name": "Akamai", "category": "cdn", "website": "https://akamai.com",
     "header_patterns": [r"X-Akamai-", r"server:\s*AkamaiGHost"], "version_regex": None,
     "cookie_patterns": [r"ak_bmsc"], "body_patterns": [],
     "meta_patterns": [], "script_patterns": [], "url_patterns": []},

    # Analytics
    {"name": "Google Analytics", "category": "analytics", "website": "https://analytics.google.com",
     "header_patterns": [], "version_regex": None,
     "cookie_patterns": [r"_ga", r"_gid"],
     "body_patterns": [r"google-analytics\.com/analytics\.js", r"gtag\("],
     "meta_patterns": [], "script_patterns": [r"google-analytics\.com", r"googletagmanager\.com/gtag"], "url_patterns": []},
    {"name": "Google Tag Manager", "category": "analytics", "website": "https://tagmanager.google.com",
     "header_patterns": [], "version_regex": None,
     "cookie_patterns": [], "body_patterns": [r"googletagmanager\.com/gtm\.js"],
     "meta_patterns": [], "script_patterns": [r"googletagmanager\.com/gtm"], "url_patterns": []},

    # DevOps / Monitoring
    {"name": "Jenkins", "category": "devops", "website": "https://jenkins.io",
     "header_patterns": [r"X-Jenkins", r"X-Hudson"], "version_regex": r"Jenkins/([\d.]+)",
     "cookie_patterns": [r"JSESSIONID\."],
     "body_patterns": [r"<title>Dashboard \[Jenkins\]", r"jenkins-favicon"],
     "meta_patterns": [], "script_patterns": [r"/jenkins/static/"], "url_patterns": [r"/jenkins/", r"/job/"]},
    {"name": "GitLab", "category": "devops", "website": "https://gitlab.com",
     "header_patterns": [r"X-Gitlab-"], "version_regex": r"GitLab/([\d.]+)",
     "cookie_patterns": [r"_gitlab_session"],
     "body_patterns": [r"GitLab", r"gl-emoji"],
     "meta_patterns": [r'<meta[^>]+content=["\']GitLab'],
     "script_patterns": [], "url_patterns": [r"/-/merge_requests"]},
    {"name": "Grafana", "category": "monitoring", "website": "https://grafana.com",
     "header_patterns": [r"X-Grafana-"], "version_regex": r'grafana[/\s@-]([\d.]+)',
     "cookie_patterns": [r"grafana_sess"],
     "body_patterns": [r"Grafana", r"grafana-app"],
     "meta_patterns": [], "script_patterns": [r"grafana\.min\.js"], "url_patterns": [r"/grafana/"]},
    {"name": "Kibana", "category": "monitoring", "website": "https://elastic.co/kibana",
     "header_patterns": [r"kbn-name"], "version_regex": r"kbn-version:\s*([\d.]+)",
     "cookie_patterns": [],
     "body_patterns": [r"kbn-injected-metadata", r"kibana"],
     "meta_patterns": [], "script_patterns": [r"bundles/kibana"], "url_patterns": [r"/app/kibana"]},

    # Application Servers / DB UI
    {"name": "Apache Tomcat", "category": "application-server", "website": "https://tomcat.apache.org",
     "header_patterns": [], "version_regex": r"Apache Tomcat/([\d.]+)",
     "cookie_patterns": [r"JSESSIONID"],
     "body_patterns": [r"Apache Tomcat", r"Tomcat Web Application Manager"],
     "meta_patterns": [], "script_patterns": [], "url_patterns": [r"/manager/html"]},
    {"name": "phpMyAdmin", "category": "database-ui", "website": "https://phpmyadmin.net",
     "header_patterns": [], "version_regex": r"phpMyAdmin ([\d.]+)",
     "cookie_patterns": [r"phpMyAdmin", r"pmaUser"],
     "body_patterns": [r"phpMyAdmin", r"pma_", r"PMA_"],
     "meta_patterns": [r'<meta[^>]+content=["\']phpMyAdmin'],
     "script_patterns": [], "url_patterns": [r"/phpmyadmin", r"/pma"]},
    {"name": "Elasticsearch", "category": "database", "website": "https://elastic.co",
     "header_patterns": [], "version_regex": r'"number"\s*:\s*"([\d.]+)"',
     "cookie_patterns": [],
     "body_patterns": [r'"cluster_name"', r'"tagline".*"You Know, for Search"'],
     "meta_patterns": [], "script_patterns": [], "url_patterns": [r"/_cat/indices", r"/_cluster/health"]},
]


class TechFingerprinter:
    def __init__(self, headers: Dict[str, str], body: str = "", cookies: str = "", url: str = "") -> None:
        self._headers = {k.lower(): v for k, v in headers.items()}
        self._body = body
        self._cookies = cookies
        self._url = url
        self._headers_str = " ".join(f"{k}: {v}" for k, v in self._headers.items())

    def fingerprint(self) -> List[Dict[str, Any]]:
        detected: Dict[str, Dict[str, Any]] = {}
        for fp in _BUILTIN_FINGERPRINTS:
            name = fp.get("name", "")
            if not name:
                continue
            confidence = 0
            version = ""

            for pat in fp.get("header_patterns", []):
                try:
                    if re.search(pat, self._headers_str, re.IGNORECASE):
                        confidence += 40
                        version = version or self._extract_version(fp, self._headers_str)
                        break
                except re.error:
                    pass

            for pat in fp.get("cookie_patterns", []):
                try:
                    if re.search(pat, self._cookies, re.IGNORECASE):
                        confidence += 30
                        break
                except re.error:
                    pass

            for pat in fp.get("body_patterns", []):
                try:
                    if re.search(pat, self._body, re.IGNORECASE):
                        confidence += 30
                        version = version or self._extract_version(fp, self._body)
                        break
                except re.error:
                    pass

            for pat in fp.get("meta_patterns", []):
                try:
                    if re.search(pat, self._body, re.IGNORECASE):
                        confidence += 35
                        version = version or self._extract_version(fp, self._body)
                        break
                except re.error:
                    pass

            for pat in fp.get("script_patterns", []):
                try:
                    if re.search(pat, self._body, re.IGNORECASE):
                        confidence += 25
                        version = version or self._extract_version(fp, self._body)
                        break
                except re.error:
                    pass

            for pat in fp.get("url_patterns", []):
                try:
                    if re.search(pat, self._url, re.IGNORECASE):
                        confidence += 20
                        break
                except re.error:
                    pass

            if confidence >= 20:
                if name not in detected or detected[name]["confidence"] < confidence:
                    detected[name] = {
                        "name": name,
                        "category": fp.get("category", "unknown"),
                        "version": version.strip() if version else "",
                        "website": fp.get("website", ""),
                        "confidence": min(confidence, 100),
                    }

        return sorted(detected.values(), key=lambda x: -x["confidence"])

    @staticmethod
    def _extract_version(fp: Dict[str, Any], text: str) -> str:
        regex = fp.get("version_regex")
        if not regex or not text:
            return ""
        try:
            m = re.search(regex, text, re.IGNORECASE)
            if m:
                return m.group(1)
        except (re.error, IndexError):
            pass
        return ""
