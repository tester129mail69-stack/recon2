"""HTML form extraction for GODRECON web crawl."""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urljoin

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_CSRF_NAMES = {
    "csrf",
    "_token",
    "csrf_token",
    "csrftoken",
    "authenticity_token",
    "__requestverificationtoken",
    "_csrf",
    "xsrf_token",
    "x-csrf-token",
}


class FormFinder:
    """Extract and analyse HTML forms from web pages."""

    def extract_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from *html* and classify them.

        Args:
            html: Full HTML content of a page.
            base_url: URL of the page (used to resolve relative action URLs).

        Returns:
            List of form dicts with: action, method, inputs, has_csrf_token,
            form_type, injection_points, missing_csrf.
        """
        forms: List[Dict[str, Any]] = []
        for form_match in re.finditer(
            r'<form([^>]*)>(.*?)</form>', html, re.DOTALL | re.IGNORECASE
        ):
            attrs_str = form_match.group(1)
            body_str = form_match.group(2)

            action = self._attr(attrs_str, "action") or ""
            action = urljoin(base_url, action) if action else base_url
            method = (self._attr(attrs_str, "method") or "GET").upper()

            inputs = self._parse_inputs(body_str)
            has_password = any(i["type"] == "password" for i in inputs)
            has_file = any(i["type"] == "file" for i in inputs)
            has_csrf = any(
                i.get("name", "").lower().replace("-", "_") in _CSRF_NAMES
                or i.get("type") == "hidden"
                and i.get("name", "").lower().replace("-", "_") in _CSRF_NAMES
                for i in inputs
            )

            # Classify form type
            if has_password:
                form_type = "login"
            elif has_file:
                form_type = "upload"
            elif any(i.get("type") == "search" for i in inputs):
                form_type = "search"
            else:
                form_type = "generic"

            # Injection points: all text/number/hidden/search inputs
            injection_points = [
                i["name"] for i in inputs
                if i["type"] in ("text", "number", "email", "search", "hidden", "textarea", "")
                and i.get("name")
            ]

            # Missing CSRF is a medium-severity issue for POST forms
            missing_csrf = method == "POST" and not has_csrf

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
                "has_csrf_token": has_csrf,
                "form_type": form_type,
                "injection_points": injection_points,
                "missing_csrf": missing_csrf,
                "page": base_url,
            })

        return forms

    @staticmethod
    def _attr(attrs_str: str, attr: str) -> str:
        """Extract attribute value from an HTML tag attribute string.

        Args:
            attrs_str: Raw attribute portion of an HTML tag.
            attr: Attribute name to extract.

        Returns:
            Attribute value or empty string.
        """
        m = re.search(
            rf'{attr}=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE
        )
        return m.group(1) if m else ""

    @staticmethod
    def _parse_inputs(form_body: str) -> List[Dict[str, str]]:
        """Parse all ``<input>`` elements within a form body.

        Args:
            form_body: Inner HTML of a ``<form>`` element.

        Returns:
            List of input dicts with name, type, value.
        """
        inputs: List[Dict[str, str]] = []
        for inp in re.finditer(r'<input([^>]*)/?>|<textarea([^>]*)>', form_body, re.IGNORECASE):
            attrs = inp.group(1) or inp.group(2) or ""
            name_m = re.search(r'name=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            type_m = re.search(r'type=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            value_m = re.search(r'value=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            inputs.append({
                "name": name_m.group(1) if name_m else "",
                "type": (type_m.group(1) if type_m else "text").lower(),
                "value": value_m.group(1) if value_m else "",
            })
        return inputs
