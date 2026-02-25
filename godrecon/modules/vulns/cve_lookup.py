"""Multi-source CVE Lookup module for GODRECON.

Sources:
  1. NVD API v2  (US NIST — most complete, 200k+ CVEs)
  2. CVE.circl.lu (CIRCL — fast fallback)
  3. OSV.dev      (Google — open source ecosystem CVEs)

No external JSON files needed. CPE map is built-in.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Dict, List, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
_NVD_API_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CIRCL_API_BASE  = "https://cve.circl.lu/api"
_OSV_API_BASE    = "https://api.osv.dev/v1"

_DEFAULT_MAX_RESULTS = 100
_DEFAULT_RATE_LIMIT  = 0.6   # NVD allows ~5 req/s without API key

# ---------------------------------------------------------------------------
# Built-in CPE map
# ---------------------------------------------------------------------------
_BUILTIN_CPE_MAP: Dict[str, str] = {
    "apache":                   "cpe:2.3:a:apache:http_server",
    "apache http server":       "cpe:2.3:a:apache:http_server",
    "nginx":                    "cpe:2.3:a:nginx:nginx",
    "iis":                      "cpe:2.3:a:microsoft:internet_information_services",
    "microsoft iis":            "cpe:2.3:a:microsoft:internet_information_services",
    "lighttpd":                 "cpe:2.3:a:lighttpd:lighttpd",
    "caddy":                    "cpe:2.3:a:caddyserver:caddy",
    "openresty":                "cpe:2.3:a:openresty:openresty",
    "litespeed":                "cpe:2.3:a:litespeedtech:litespeed_web_server",
    "wordpress":                "cpe:2.3:a:wordpress:wordpress",
    "drupal":                   "cpe:2.3:a:drupal:drupal",
    "joomla":                   "cpe:2.3:a:joomla:joomla",
    "typo3":                    "cpe:2.3:a:typo3:typo3",
    "magento":                  "cpe:2.3:a:magento:magento",
    "shopify":                  "cpe:2.3:a:shopify:shopify",
    "prestashop":               "cpe:2.3:a:prestashop:prestashop",
    "opencart":                 "cpe:2.3:a:opencart:opencart",
    "woocommerce":              "cpe:2.3:a:woocommerce:woocommerce",
    "mediawiki":                "cpe:2.3:a:mediawiki:mediawiki",
    "ghost":                    "cpe:2.3:a:ghost:ghost",
    "moodle":                   "cpe:2.3:a:moodle:moodle",
    "php":                      "cpe:2.3:a:php:php",
    "laravel":                  "cpe:2.3:a:laravel:laravel",
    "symfony":                  "cpe:2.3:a:symfony:symfony",
    "codeigniter":              "cpe:2.3:a:codeigniter:codeigniter",
    "django":                   "cpe:2.3:a:djangoproject:django",
    "flask":                    "cpe:2.3:a:palletsprojects:flask",
    "ruby on rails":            "cpe:2.3:a:rubyonrails:ruby_on_rails",
    "rails":                    "cpe:2.3:a:rubyonrails:ruby_on_rails",
    "spring":                   "cpe:2.3:a:vmware:spring_framework",
    "spring framework":         "cpe:2.3:a:vmware:spring_framework",
    "spring boot":              "cpe:2.3:a:vmware:spring_boot",
    "struts":                   "cpe:2.3:a:apache:struts",
    "apache struts":            "cpe:2.3:a:apache:struts",
    "express":                  "cpe:2.3:a:expressjs:express",
    "expressjs":                "cpe:2.3:a:expressjs:express",
    "node.js":                  "cpe:2.3:a:nodejs:node.js",
    "nodejs":                   "cpe:2.3:a:nodejs:node.js",
    "next.js":                  "cpe:2.3:a:vercel:next.js",
    "fastapi":                  "cpe:2.3:a:tiangolo:fastapi",
    "jquery":                   "cpe:2.3:a:jquery:jquery",
    "react":                    "cpe:2.3:a:facebook:react",
    "angular":                  "cpe:2.3:a:google:angular",
    "angularjs":                "cpe:2.3:a:angularjs:angular.js",
    "vue.js":                   "cpe:2.3:a:vuejs:vue.js",
    "lodash":                   "cpe:2.3:a:lodash:lodash",
    "bootstrap":                "cpe:2.3:a:getbootstrap:bootstrap",
    "handlebars.js":            "cpe:2.3:a:handlebarsjs:handlebars",
    "mysql":                    "cpe:2.3:a:mysql:mysql",
    "mariadb":                  "cpe:2.3:a:mariadb:mariadb",
    "postgresql":               "cpe:2.3:a:postgresql:postgresql",
    "mongodb":                  "cpe:2.3:a:mongodb:mongodb",
    "redis":                    "cpe:2.3:a:redis:redis",
    "elasticsearch":            "cpe:2.3:a:elastic:elasticsearch",
    "cassandra":                "cpe:2.3:a:apache:cassandra",
    "couchdb":                  "cpe:2.3:a:apache:couchdb",
    "memcached":                "cpe:2.3:a:memcached:memcached",
    "sqlite":                   "cpe:2.3:a:sqlite:sqlite",
    "tomcat":                   "cpe:2.3:a:apache:tomcat",
    "apache tomcat":            "cpe:2.3:a:apache:tomcat",
    "jboss":                    "cpe:2.3:a:redhat:jboss",
    "wildfly":                  "cpe:2.3:a:redhat:wildfly",
    "weblogic":                 "cpe:2.3:a:oracle:weblogic_server",
    "websphere":                "cpe:2.3:a:ibm:websphere_application_server",
    "jetty":                    "cpe:2.3:a:eclipse:jetty",
    "jenkins":                  "cpe:2.3:a:jenkins:jenkins",
    "gitlab":                   "cpe:2.3:a:gitlab:gitlab",
    "gitea":                    "cpe:2.3:a:gitea:gitea",
    "grafana":                  "cpe:2.3:a:grafana:grafana",
    "kibana":                   "cpe:2.3:a:elastic:kibana",
    "logstash":                 "cpe:2.3:a:elastic:logstash",
    "prometheus":               "cpe:2.3:a:prometheus:prometheus",
    "zabbix":                   "cpe:2.3:a:zabbix:zabbix",
    "kubernetes":               "cpe:2.3:a:kubernetes:kubernetes",
    "docker":                   "cpe:2.3:a:docker:docker",
    "traefik":                  "cpe:2.3:a:traefik:traefik",
    "vault":                    "cpe:2.3:a:hashicorp:vault",
    "consul":                   "cpe:2.3:a:hashicorp:consul",
    "roundcube":                "cpe:2.3:a:roundcube:webmail",
    "zimbra":                   "cpe:2.3:a:zimbra:collaboration",
    "keycloak":                 "cpe:2.3:a:redhat:keycloak",
    "phpmyadmin":               "cpe:2.3:a:phpmyadmin:phpmyadmin",
    "openssl":                  "cpe:2.3:a:openssl:openssl",
    "log4j":                    "cpe:2.3:a:apache:log4j",
    "apache shiro":             "cpe:2.3:a:apache:shiro",
    "shiro":                    "cpe:2.3:a:apache:shiro",
    "jackson":                  "cpe:2.3:a:fasterxml:jackson-databind",
    "exim":                     "cpe:2.3:a:exim:exim",
    "postfix":                  "cpe:2.3:a:wietse_venema:postfix",
    "sendmail":                 "cpe:2.3:a:sendmail:sendmail",
    "openssh":                  "cpe:2.3:a:openbsd:openssh",
    "ssh":                      "cpe:2.3:a:openbsd:openssh",
    "vsftpd":                   "cpe:2.3:a:vsftpd_project:vsftpd",
    "proftpd":                  "cpe:2.3:a:proftpd:proftpd",
    "pure-ftpd":                "cpe:2.3:a:pureftpd:pure-ftpd",
    "samba":                    "cpe:2.3:a:samba:samba",
    "openldap":                 "cpe:2.3:a:openldap:openldap",
    "bind":                     "cpe:2.3:a:isc:bind",
    "dnsmasq":                  "cpe:2.3:a:thekelleys:dnsmasq",
    "haproxy":                  "cpe:2.3:a:haproxy:haproxy",
    "varnish":                  "cpe:2.3:a:varnish-cache:varnish",
    "squid":                    "cpe:2.3:a:squid-cache:squid",
    "wkhtmltopdf":              "cpe:2.3:a:wkhtmltopdf:wkhtmltopdf",
    "imagemagick":              "cpe:2.3:a:imagemagick:imagemagick",
    "ghostscript":              "cpe:2.3:a:artifex:ghostscript",
    "cups":                     "cpe:2.3:a:apple:cups",
    "xwiki":                    "cpe:2.3:a:xwiki:xwiki",
    "confluence":               "cpe:2.3:a:atlassian:confluence_server",
    "jira":                     "cpe:2.3:a:atlassian:jira",
    "bitbucket":                "cpe:2.3:a:atlassian:bitbucket",
    "bamboo":                   "cpe:2.3:a:atlassian:bamboo",
    "sonarqube":                "cpe:2.3:a:sonarsource:sonarqube",
    "nexus":                    "cpe:2.3:a:sonatype:nexus_repository_manager",
    "artifactory":              "cpe:2.3:a:jfrog:artifactory",
    "mattermost":               "cpe:2.3:a:mattermost:mattermost_server",
    "rocketchat":               "cpe:2.3:a:rocket.chat:rocket.chat",
    "nextcloud":                "cpe:2.3:a:nextcloud:nextcloud_server",
    "owncloud":                 "cpe:2.3:a:owncloud:owncloud",
    "phabricator":              "cpe:2.3:a:phacility:phabricator",
    "redmine":                  "cpe:2.3:a:redmine:redmine",
    "mantisbt":                 "cpe:2.3:a:mantisbt:mantisbt",
    "glpi":                     "cpe:2.3:a:glpi-project:glpi",
    "cacti":                    "cpe:2.3:a:cacti:cacti",
    "nagios":                   "cpe:2.3:a:nagios:nagios",
    "icinga":                   "cpe:2.3:a:icinga:icinga",
    "centreon":                 "cpe:2.3:a:centreon:centreon",
    "netdata":                  "cpe:2.3:a:netdata:netdata",
    "portainer":                "cpe:2.3:a:portainer:portainer",
    "rancher":                  "cpe:2.3:a:rancher:rancher",
    "opensearch":               "cpe:2.3:a:amazon:opensearch",
    "solr":                     "cpe:2.3:a:apache:solr",
    "activemq":                 "cpe:2.3:a:apache:activemq",
    "rabbitmq":                 "cpe:2.3:a:pivotal_software:rabbitmq",
    "kafka":                    "cpe:2.3:a:apache:kafka",
    "zookeeper":                "cpe:2.3:a:apache:zookeeper",
    "hadoop":                   "cpe:2.3:a:apache:hadoop",
    "spark":                    "cpe:2.3:a:apache:spark",
    "airflow":                  "cpe:2.3:a:apache:airflow",
    "superset":                 "cpe:2.3:a:apache:superset",
    "metabase":                 "cpe:2.3:a:metabase:metabase",
    "grafana loki":             "cpe:2.3:a:grafana:loki",
    "telerik":                  "cpe:2.3:a:telerik:ui_for_asp.net_ajax",
    "dotcms":                   "cpe:2.3:a:dotcms:dotcms",
    "liferay":                  "cpe:2.3:a:liferay:liferay_portal",
    "kentico":                  "cpe:2.3:a:kentico:kentico_cms",
    "sitecore":                 "cpe:2.3:a:sitecore:experience_platform",
    "umbraco":                  "cpe:2.3:a:umbraco:umbraco_cms",
    "orchard":                  "cpe:2.3:a:orchardproject:orchard",
    "coldfusion":               "cpe:2.3:a:adobe:coldfusion",
    "adobe coldfusion":         "cpe:2.3:a:adobe:coldfusion",
    "websocket":                "",
    "cloudflare waf":           "",
    "cloudflare cdn":           "",
    "google analytics":         "",
    "google tag manager":       "",
}

# ---------------------------------------------------------------------------
# OSV ecosystem mapping — tech name → OSV ecosystem string
# ---------------------------------------------------------------------------
_OSV_ECOSYSTEM_MAP: Dict[str, str] = {
    "wordpress":    "WordPress",
    "drupal":       "Packagist",
    "joomla":       "Packagist",
    "laravel":      "Packagist",
    "symfony":      "Packagist",
    "codeigniter":  "Packagist",
    "php":          "Packagist",
    "django":       "PyPI",
    "flask":        "PyPI",
    "fastapi":      "PyPI",
    "rails":        "RubyGems",
    "ruby on rails":"RubyGems",
    "jquery":       "npm",
    "react":        "npm",
    "angular":      "npm",
    "angularjs":    "npm",
    "vue.js":       "npm",
    "lodash":       "npm",
    "bootstrap":    "npm",
    "express":      "npm",
    "expressjs":    "npm",
    "next.js":      "npm",
    "node.js":      "npm",
    "handlebars.js":"npm",
    "log4j":        "Maven",
    "spring":       "Maven",
    "spring boot":  "Maven",
    "spring framework": "Maven",
    "struts":       "Maven",
    "jackson":      "Maven",
    "shiro":        "Maven",
}

# ---------------------------------------------------------------------------
# NVD keyword search map — tech name → NVD keyword search string
# ---------------------------------------------------------------------------
_NVD_KEYWORD_MAP: Dict[str, str] = {
    "apache":           "apache http server",
    "apache http server":"apache http server",
    "nginx":            "nginx",
    "iis":              "microsoft iis",
    "microsoft iis":    "microsoft iis",
    "wordpress":        "wordpress",
    "drupal":           "drupal",
    "joomla":           "joomla",
    "php":              "php",
    "django":           "django",
    "flask":            "flask",
    "rails":            "ruby on rails",
    "ruby on rails":    "ruby on rails",
    "spring boot":      "spring boot",
    "spring":           "spring framework",
    "struts":           "apache struts",
    "apache struts":    "apache struts",
    "log4j":            "log4j",
    "tomcat":           "apache tomcat",
    "apache tomcat":    "apache tomcat",
    "jenkins":          "jenkins",
    "gitlab":           "gitlab",
    "elasticsearch":    "elasticsearch",
    "redis":            "redis",
    "mongodb":          "mongodb",
    "mysql":            "mysql",
    "postgresql":       "postgresql",
    "jquery":           "jquery",
    "openssl":          "openssl",
    "phpmyadmin":       "phpmyadmin",
    "grafana":          "grafana",
    "kibana":           "kibana",
    "kubernetes":       "kubernetes",
    "docker":           "docker",
    "confluence":       "atlassian confluence",
    "jira":             "atlassian jira",
    "weblogic":         "oracle weblogic",
    "coldfusion":       "adobe coldfusion",
    "telerik":          "telerik",
    "liferay":          "liferay portal",
    "nextcloud":        "nextcloud",
    "zimbra":           "zimbra",
    "roundcube":        "roundcube",
    "magento":          "magento",
    "shopware":         "shopware",
    "moodle":           "moodle",
    "mediawiki":        "mediawiki",
    "activemq":         "apache activemq",
    "solr":             "apache solr",
    "airflow":          "apache airflow",
    "superset":         "apache superset",
    "shiro":            "apache shiro",
    "zabbix":           "zabbix",
    "cacti":            "cacti",
}

_VERSION_PATTERNS: List[re.Pattern] = [
    re.compile(r'(?:version|ver|v)[/\s:="\']?(\d+\.\d+[\.\d]*)', re.IGNORECASE),
    re.compile(r'(\d+\.\d+\.\d+(?:\.\d+)?)'),
    re.compile(r'(\d+\.\d+)'),
]


def _extract_version(text: str) -> Optional[str]:
    if not text:
        return None
    for pat in _VERSION_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1)
    return None


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"


class CVELookup:
    """Multi-source CVE lookup: NVD API v2 + circl.lu + OSV.dev.

    Args:
        http_client: Shared AsyncHTTPClient.
        max_results: Max CVEs per technology per source.
        rate_limit: Seconds between requests.
        nvd_api_key: Optional NVD API key (increases rate limit 10x).
    """

    def __init__(
        self,
        http_client: AsyncHTTPClient,
        max_results: int = _DEFAULT_MAX_RESULTS,
        rate_limit: float = _DEFAULT_RATE_LIMIT,
        nvd_api_key: Optional[str] = None,
    ) -> None:
        self._http        = http_client
        self._max_results = max_results
        self._rate_limit  = rate_limit
        self._nvd_api_key = nvd_api_key
        self._cache: Dict[str, List[Dict[str, Any]]] = {}
        self._sem         = asyncio.Semaphore(5)
        self._nvd_sem     = asyncio.Semaphore(2)   # NVD is stricter
        self._osv_sem     = asyncio.Semaphore(5)

    def _resolve_cpe(self, tech_name: str) -> Optional[str]:
        key = tech_name.lower().strip()
        if key in _BUILTIN_CPE_MAP:
            cpe = _BUILTIN_CPE_MAP[key]
            return cpe if cpe else None
        for known_key, cpe in _BUILTIN_CPE_MAP.items():
            if known_key and known_key in key:
                return cpe if cpe else None
        for known_key, cpe in _BUILTIN_CPE_MAP.items():
            if key and known_key.startswith(key):
                return cpe if cpe else None
        return None

    def _resolve_nvd_keyword(self, tech_name: str) -> Optional[str]:
        key = tech_name.lower().strip()
        return _NVD_KEYWORD_MAP.get(key) or _NVD_KEYWORD_MAP.get(key.split()[0])

    def _resolve_osv_ecosystem(self, tech_name: str) -> Optional[str]:
        key = tech_name.lower().strip()
        return _OSV_ECOSYSTEM_MAP.get(key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def lookup_technology(
        self, tech_name: str, version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if not version:
            version = _extract_version(tech_name)
        cache_key = f"{tech_name}:{version or ''}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Run all 3 sources concurrently
        results = await asyncio.gather(
            self._fetch_nvd(tech_name, version),
            self._fetch_circl(tech_name, version),
            self._fetch_osv(tech_name, version),
            return_exceptions=True,
        )

        # Merge and deduplicate by CVE ID
        merged: Dict[str, Dict[str, Any]] = {}
        for r in results:
            if isinstance(r, list):
                for cve in r:
                    cve_id = cve.get("id", "")
                    if not cve_id:
                        continue
                    if cve_id not in merged:
                        merged[cve_id] = cve
                    else:
                        # Keep the entry with the higher CVSS score
                        if cve.get("cvss", 0) > merged[cve_id].get("cvss", 0):
                            merged[cve_id] = cve

        cves = list(merged.values())
        # Sort by CVSS descending
        cves.sort(key=lambda x: x.get("cvss", 0), reverse=True)
        cves = cves[:self._max_results]

        logger.info(
            "Total CVEs for %s (v%s): %d (from NVD+CIRCL+OSV)",
            tech_name, version or "any", len(cves)
        )
        self._cache[cache_key] = cves
        return cves

    async def lookup_technologies(
        self, technologies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        tasks = []
        for tech in technologies:
            name = tech.get("name", "").strip()
            if not name:
                continue
            # Skip techs that are purely tracking/CDN with no CVEs
            cpe = self._resolve_cpe(name)
            nvd_kw = self._resolve_nvd_keyword(name)
            osv_eco = self._resolve_osv_ecosystem(name)
            if not cpe and not nvd_kw and not osv_eco:
                logger.debug("Skipping CVE lookup for %s — no source mapping", name)
                continue

            version = (
                tech.get("version")
                or _extract_version(tech.get("raw_header", ""))
                or _extract_version(tech.get("raw_body", ""))
                or _extract_version(tech.get("description", ""))
            )
            if version:
                version = version.lstrip("vV").strip()
            tasks.append(self._lookup_with_context(name, version or None))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: List[Dict[str, Any]] = []
        seen_ids: set = set()
        for r in results:
            if isinstance(r, list):
                for cve in r:
                    cve_id = cve.get("id", "")
                    if cve_id and cve_id not in seen_ids:
                        seen_ids.add(cve_id)
                        findings.append(cve)
            elif isinstance(r, Exception):
                logger.debug("CVE lookup task error: %s", r)

        # Final sort by CVSS
        findings.sort(key=lambda x: x.get("cvss", 0), reverse=True)
        logger.info("Total unique CVEs found across all technologies: %d", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Source 1: NVD API v2
    # ------------------------------------------------------------------

    async def _fetch_nvd(
        self, tech_name: str, version: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Query NVD API v2 by CPE or keyword search."""
        async with self._nvd_sem:
            await asyncio.sleep(self._rate_limit)

            cpe = self._resolve_cpe(tech_name)
            keyword = self._resolve_nvd_keyword(tech_name)

            if not cpe and not keyword:
                return []

            headers: Dict[str, str] = {}
            if self._nvd_api_key:
                headers["apiKey"] = self._nvd_api_key

            results: List[Dict[str, Any]] = []

            # Try CPE-based search first (most accurate)
            if cpe:
                try:
                    cpe_str = f"{cpe}:{version}:*:*:*:*:*:*:*" if version else f"{cpe}:*:*:*:*:*:*:*:*"
                    url = f"{_NVD_API_BASE}?cpeName={cpe_str}&resultsPerPage={self._max_results}"
                    resp = await self._http.get(url, headers=headers)
                    if resp.get("status") == 200:
                        body = resp.get("body", "") or ""
                        data = json.loads(body) if body else {}
                        vulns = data.get("vulnerabilities", [])
                        results.extend(self._parse_nvd_items(vulns, tech_name, version))
                        logger.debug("NVD CPE search for %s: %d CVEs", tech_name, len(results))
                except Exception as exc:
                    logger.debug("NVD CPE fetch failed for %s: %s", tech_name, exc)

            # Also try keyword search to catch more CVEs
            if keyword and len(results) < self._max_results:
                try:
                    kw_encoded = keyword.replace(" ", "%20")
                    url = f"{_NVD_API_BASE}?keywordSearch={kw_encoded}&resultsPerPage={self._max_results}"
                    if version:
                        url += f"&virtualMatchString=cpe:2.3:*:*:*:{version}"
                    resp = await self._http.get(url, headers=headers)
                    if resp.get("status") == 200:
                        body = resp.get("body", "") or ""
                        data = json.loads(body) if body else {}
                        vulns = data.get("vulnerabilities", [])
                        kw_results = self._parse_nvd_items(vulns, tech_name, version)
                        results.extend(kw_results)
                        logger.debug("NVD keyword search for '%s': %d CVEs", keyword, len(kw_results))
                except Exception as exc:
                    logger.debug("NVD keyword fetch failed for %s: %s", tech_name, exc)

            return results

    @staticmethod
    def _parse_nvd_items(
        vulns: List[Dict[str, Any]], tech_name: str, version: Optional[str]
    ) -> List[Dict[str, Any]]:
        parsed = []
        for item in vulns:
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "")
            if not cve_id:
                continue

            # Description
            descs   = cve_data.get("descriptions", [])
            summary = next(
                (d["value"] for d in descs if d.get("lang") == "en"),
                "No description available"
            )

            # CVSS score — prefer v3.1, then v3.0, then v2
            metrics  = cve_data.get("metrics", {})
            cvss     = 0.0
            severity = "info"
            cvss_ver = ""

            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss      = float(cvss_data.get("baseScore", 0.0))
                    cvss_ver  = cvss_data.get("version", "")
                    severity  = _cvss_to_severity(cvss)
                    break

            # References
            refs = [
                r.get("url", "") for r in cve_data.get("references", [])
                if r.get("url")
            ]

            # CWE
            weaknesses = cve_data.get("weaknesses", [])
            cwe = ""
            for w in weaknesses:
                for desc in w.get("description", []):
                    if desc.get("lang") == "en":
                        cwe = desc.get("value", "")
                        break
                if cwe:
                    break

            # Published date
            published = cve_data.get("published", "")[:10]
            modified  = cve_data.get("lastModified", "")[:10]

            # Affected versions from CPE matches
            affected_versions: List[str] = []
            for cfg in cve_data.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            vi = cpe_match.get("versionStartIncluding", "")
                            ve = cpe_match.get("versionEndExcluding", "")
                            vei = cpe_match.get("versionEndIncluding", "")
                            if vi or ve or vei:
                                ver_str = ""
                                if vi:
                                    ver_str += f">={vi}"
                                if ve:
                                    ver_str += f" <{ve}"
                                if vei:
                                    ver_str += f" <={vei}"
                                affected_versions.append(ver_str.strip())

            parsed.append({
                "id":                cve_id,
                "summary":           summary,
                "cvss":              cvss,
                "cvss_version":      cvss_ver,
                "severity":          severity,
                "published":         published,
                "modified":          modified,
                "references":        refs[:10],
                "cwe":               cwe,
                "affected_versions": affected_versions[:10],
                "source":            "NVD",
            })
        return parsed

    # ------------------------------------------------------------------
    # Source 2: CVE.circl.lu
    # ------------------------------------------------------------------

    async def _fetch_circl(
        self, tech_name: str, version: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Query CVE.circl.lu API."""
        async with self._sem:
            await asyncio.sleep(self._rate_limit)

            cpe = self._resolve_cpe(tech_name)
            if not cpe:
                return []

            cpe_query = f"{cpe}:{version}" if version else cpe
            url = f"{_CIRCL_API_BASE}/cvefor/{cpe_query}"

            try:
                resp = await self._http.get(url)
                if resp.get("status") != 200:
                    return []
                body = resp.get("body", "") or ""
                raw  = json.loads(body) if body else []
                if not isinstance(raw, list):
                    return []
                results = [
                    self._parse_circl_cve(c)
                    for c in raw[:self._max_results]
                    if isinstance(c, dict)
                ]
                logger.debug("CIRCL CVEs for %s: %d", tech_name, len(results))
                return results
            except Exception as exc:
                logger.debug("CIRCL fetch failed for %s: %s", tech_name, exc)
                return []

    @staticmethod
    def _parse_circl_cve(raw: Dict[str, Any]) -> Dict[str, Any]:
        cvss_raw = raw.get("cvss3") or raw.get("cvss") or 0.0
        try:
            cvss = float(cvss_raw)
        except (TypeError, ValueError):
            cvss = 0.0

        affected: List[str] = []
        for cfg in raw.get("vulnerable_configuration", []):
            if isinstance(cfg, str):
                parts = cfg.split(":")
                if len(parts) >= 6 and parts[5] not in ("*", "-", ""):
                    affected.append(parts[5])

        return {
            "id":                raw.get("id", ""),
            "summary":           raw.get("summary", "No description available"),
            "cvss":              cvss,
            "cvss_version":      "CIRCL",
            "severity":          _cvss_to_severity(cvss),
            "published":         raw.get("Published", "")[:10],
            "modified":          raw.get("Modified", "")[:10],
            "references":        raw.get("references", [])[:10],
            "cwe":               raw.get("cwe", ""),
            "affected_versions": affected[:10],
            "source":            "CIRCL",
        }

    # ------------------------------------------------------------------
    # Source 3: OSV.dev (Google)
    # ------------------------------------------------------------------

    async def _fetch_osv(
        self, tech_name: str, version: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Query OSV.dev API for open-source ecosystem CVEs."""
        async with self._osv_sem:
            await asyncio.sleep(self._rate_limit * 0.5)

            ecosystem = self._resolve_osv_ecosystem(tech_name)
            if not ecosystem:
                return []

            # OSV package name — use lowercase tech name
            pkg_name = tech_name.lower().strip()
            # Common package name corrections
            _pkg_corrections = {
                "ruby on rails": "rails",
                "node.js": "node",
                "angularjs": "angular",
                "vue.js": "vue",
                "handlebars.js": "handlebars",
            }
            pkg_name = _pkg_corrections.get(pkg_name, pkg_name)

            payload: Dict[str, Any] = {
                "package": {
                    "name": pkg_name,
                    "ecosystem": ecosystem,
                }
            }
            if version:
                payload["version"] = version

            url = f"{_OSV_API_BASE}/query"
            try:
                resp = await self._http.request(
                    method="POST",
                    url=url,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps(payload).encode(),
                )
                if resp.get("status") != 200:
                    return []
                body = resp.get("body", "") or ""
                data = json.loads(body) if body else {}
                vulns = data.get("vulns", [])
                results = [
                    self._parse_osv_vuln(v)
                    for v in vulns[:self._max_results]
                    if isinstance(v, dict)
                ]
                logger.debug("OSV CVEs for %s/%s: %d", ecosystem, pkg_name, len(results))
                return results
            except Exception as exc:
                logger.debug("OSV fetch failed for %s: %s", tech_name, exc)
                return []

    @staticmethod
    def _parse_osv_vuln(raw: Dict[str, Any]) -> Dict[str, Any]:
        osv_id = raw.get("id", "")

        # Find the CVE alias if available
        cve_id = osv_id
        for alias in raw.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        summary  = raw.get("summary", "") or raw.get("details", "")[:300]
        cvss     = 0.0
        severity = "info"

        # Extract CVSS from severity array
        for sev in raw.get("severity", []):
            score_str = sev.get("score", "")
            # CVSS vector strings contain the base score
            m = re.search(r"CVSS:[\d.]+/AV:[^/]+(?:/[^/]+)+", score_str)
            if m:
                # Try to get numeric score from database_specific
                pass
            db_specific = raw.get("database_specific", {})
            cvss_val = db_specific.get("cvss_score") or db_specific.get("severity_score")
            if cvss_val:
                try:
                    cvss = float(cvss_val)
                    severity = _cvss_to_severity(cvss)
                except (TypeError, ValueError):
                    pass
            if not cvss:
                sev_label = db_specific.get("severity", "").upper()
                severity_map = {
                    "CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0
                }
                cvss = severity_map.get(sev_label, 0.0)
                severity = _cvss_to_severity(cvss)
            break

        # References
        refs = [r.get("url", "") for r in raw.get("references", []) if r.get("url")]

        # Affected versions
        affected_versions: List[str] = []
        for aff in raw.get("affected", []):
            for rng in aff.get("ranges", []):
                for event in rng.get("events", []):
                    introduced = event.get("introduced", "")
                    fixed = event.get("fixed", "")
                    if introduced and introduced != "0":
                        affected_versions.append(f">={introduced}")
                    if fixed:
                        affected_versions.append(f"fixed in {fixed}")

        return {
            "id":                cve_id,
            "osv_id":            osv_id,
            "summary":           summary,
            "cvss":              cvss,
            "cvss_version":      "OSV",
            "severity":          severity,
            "published":         raw.get("published", "")[:10],
            "modified":          raw.get("modified", "")[:10],
            "references":        refs[:10],
            "cwe":               "",
            "affected_versions": list(dict.fromkeys(affected_versions))[:10],
            "source":            "OSV",
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _lookup_with_context(
        self, tech_name: str, version: Optional[str]
    ) -> List[Dict[str, Any]]:
        cves = await self.lookup_technology(tech_name, version)
        for cve in cves:
            cve["technology"]       = tech_name
            cve["detected_version"] = version or "unknown"
        return cves
