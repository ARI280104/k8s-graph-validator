"""
Guardrail Kubernetes (K8s) cluster graph/API validator.

Uses the existing Guardrail browser login/session, opens the Kubernetes cluster
list, discovers cluster detail links, captures XHR/fetch API responses while
the cluster monitoring view loads, and writes CSV + JSON debug output.

Install:
    py -m pip install playwright
    py -m playwright install chromium

Run:
    py k8s_cluster_graph_validator.py

If your Guardrail detail-page URL pattern differs, update CLUSTER_LINK_HINTS
below after inspecting a cluster link in the browser.
"""
import asyncio
import csv
import json
import os
import re
from datetime import datetime
from urllib.parse import parse_qs, unquote, urljoin, urlparse

from playwright.async_api import async_playwright, Page, Response


# --------------------------- CONFIGURATION ---------------------------

BASE_URL = "https://times.guardrail.in"
DASHBOARD_URL = f"{BASE_URL}/dashboard/home"
K8S_CLUSTER_LIST_URL = f"{BASE_URL}/dashboard/k8s-cluster/k8s-cluster-list"

PROFILE_DIR = "guardrail_k8s_profile"
OUTPUT_CSV = "guardrail_k8s_cluster_graph_report.csv"
DEBUG_DIR = "guardrail_k8s_debug"

LOGIN_TIMEOUT_SECONDS = 300
PAGE_LOAD_TIMEOUT_MS = 60_000
GRAPH_WAIT_MS = 8_000
PAGINATION_WAIT_MS = 2_500
MANUAL_PAGE_SETUP = False  # account/cluster sweep must run without per-account prompts

# Used to recognize likely Kubernetes monitoring endpoints. The script also
# records other /api/ XHR/fetch responses so newly discovered endpoints aren't
# silently missed.
GRAPH_API_PATTERNS = [
    "/api/k8s-clusters/cluster",
    "/api/k8s-clusters/monmetrics",
    "/api/cluster/k8s-cluster-influxdata",
    "/api/common/project-access",
    "/api/servers/is-monitoring-enabled",
    "/api/servers/namespacess",
]

DATA_FIELDS = [
    "metricdata", "data", "result", "results", "series",
    "values", "points", "datapoints", "metrics",
]

# Anchor hrefs are inspected for these hints. The cluster-list URL itself is
# excluded. Add the actual detail route hint here if your UI uses another route.
CLUSTER_LINK_HINTS = (
    "k8s-cluster",
    "k8s_cluster",
    "cluster-details",
    "cluster-detail",
)

captured_responses = []
active_cluster_label = None
active_namespace_label = "All"
list_api_payloads = []
active_account_label = "Current account"


# --------------------------- HELPERS ---------------------------------

def normalize_text(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def safe_filename(value):
    value = normalize_text(value)
    value = re.sub(r'[<>:"/\\|?*]', "_", value)
    return value[:150] or "unknown"


def is_known_k8s_api(url):
    lowered = url.lower()
    return any(pattern in lowered for pattern in GRAPH_API_PATTERNS)


def extract_cluster_id(url):
    """Read common cluster ID query parameters or a final numeric path segment."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    for key in ("id", "clusterId", "cluster_id", "k8sClusterId", "k8s_cluster_id"):
        value = params.get(key, [""])[0]
        if value:
            return value
    match = re.search(r"/(?:cluster-details|cluster-detail|k8s-cluster)/([^/?#]+)", parsed.path, re.I)
    return unquote(match.group(1)) if match else ""


def extract_graph_name(url, body=None):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for key in ("metric", "metrics", "graph", "graph_name", "name", "type",
                "measurement", "field", "panel"):
        value = query.get(key, [""])[0]
        if value:
            return unquote(normalize_text(value))

    if isinstance(body, dict):
        for key in ("metric", "metric_name", "graph", "graph_name", "name", "title"):
            value = body.get(key)
            if isinstance(value, str) and value.strip():
                return normalize_text(value)

    path = parsed.path.rstrip("/").split("/")
    return path[-1] if path and path[-1] else "Unknown"


def has_non_empty_value(value):
    if value is None:
        return False
    if isinstance(value, (list, dict)):
        if not value:
            return False
        items = value.values() if isinstance(value, dict) else value
        return any(has_non_empty_value(item) for item in items)
    return True


def analyze_response(status_code, body):
    if status_code >= 400:
        return "API ERROR", f"HTTP {status_code}"
    if body is None:
        return "NO DATA", "Response was not valid JSON or body was empty"
    if isinstance(body, list):
        return ("DATA AVAILABLE", f"{len(body)} records/items") if body else ("NO DATA", "Empty array")
    if isinstance(body, dict):
        if not body:
            return "NO DATA", "Empty JSON object"
        matched = [field for field in DATA_FIELDS if field in body]
        if not matched:
            # Some endpoints return metadata or an object whose schema is not
            # one of the known graph-data shapes; don't incorrectly call it empty.
            return "UNKNOWN", "JSON received; no recognized graph-data field"
        for field in matched:
            value = body[field]
            if not has_non_empty_value(value):
                return "NO DATA", f"{field} is empty/null"
        return "DATA AVAILABLE", f"Recognized field(s): {', '.join(matched)}"
    return "UNKNOWN", f"Unsupported JSON type: {type(body).__name__}"


def walk_json_for_clusters(value, found):
    """Recursively find cluster-like objects in list API payloads."""
    if isinstance(value, dict):
        lower_keys = {str(k).lower(): k for k in value.keys()}
        id_keys = ("id", "clusterid", "cluster_id", "k8sclusterid", "k8s_cluster_id")
        name_keys = ("name", "clustername", "cluster_name", "k8sclustername", "k8s_cluster_name")
        ident = next((value[lower_keys[k]] for k in id_keys if k in lower_keys and value[lower_keys[k]] is not None), None)
        name = next((value[lower_keys[k]] for k in name_keys if k in lower_keys and value[lower_keys[k]]), None)
        # Require both a usable identifier and a human-readable name; this avoids
        # treating unrelated nested API objects as clusters.
        if ident is not None and name and not isinstance(ident, (dict, list)):
            ident = str(ident).strip()
            name = normalize_text(name)
            if ident and name:
                url = f"{BASE_URL}/dashboard/k8s-cluster/k8s-cluster-details?tabindex=monitoring&id={ident}"
                found[ident] = {"name": name, "url": url, "id": ident}
        for child in value.values():
            walk_json_for_clusters(child, found)
    elif isinstance(value, list):
        for child in value:
            walk_json_for_clusters(child, found)


async def list_response_listener(response: Response):
    """Capture API payloads while the cluster-list page is loading."""
    try:
        if response.request.resource_type not in ("xhr", "fetch"):
            return
        if "/api/" not in response.url.lower():
            return
        body = await response.json()
        list_api_payloads.append({"url": response.url, "status": response.status, "body": body})
    except Exception:
        return


async def response_listener(response: Response):
    if active_cluster_label is None:
        return
    try:
        if response.request.resource_type not in ("xhr", "fetch"):
            return
    except Exception:
        return

    url = response.url
    if "/api/" not in url.lower():
        return

    try:
        body = await response.json()
    except Exception:
        body = None

    captured_responses.append({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "cluster": active_cluster_label,
        "url": url,
        "status": response.status,
        "body": body,
        "known_pattern": is_known_k8s_api(url),
    })


async def ensure_authenticated(page: Page):
    print("\nOpening Guardrail...")
    await page.goto(DASHBOARD_URL, wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT_MS)
    await page.wait_for_timeout(3500)

    if "/dashboard/" in page.url.lower():
        print("Guardrail dashboard session detected.")
        return

    print("\nManual authentication required in the opened browser.")
    print("Complete SSO/Gmail login, password and OTP, then return to Guardrail.")
    start = asyncio.get_running_loop().time()
    while asyncio.get_running_loop().time() - start < LOGIN_TIMEOUT_SECONDS:
        await page.wait_for_timeout(1500)
        if "/dashboard/" in page.url.lower():
            print("Authentication successful.")
            return
    raise RuntimeError("Login timed out: Guardrail dashboard was not reached.")


async def find_next_button(page: Page):
    selectors = [
        "li.ant-pagination-next:not(.ant-pagination-disabled) button",
        "button.mat-mdc-paginator-navigation-next",
        "button.mat-paginator-navigation-next",
        "button[aria-label*='next' i]",
        "a[aria-label*='next' i]",
    ]
    for selector in selectors:
        locator = page.locator(selector)
        try:
            for i in range(await locator.count()):
                button = locator.nth(i)
                if not await button.is_visible() or await button.is_disabled():
                    continue
                if (await button.get_attribute("aria-disabled")) == "true":
                    continue
                classes = (await button.get_attribute("class")) or ""
                if "disabled" in classes.lower():
                    continue
                return button
        except Exception:
            continue

    try:
        button = page.get_by_role("button", name=re.compile(r"^\s*next\s*$", re.I)).last
        if await button.count() and await button.is_visible() and not await button.is_disabled():
            return button
    except Exception:
        pass
    return None


async def try_set_max_page_size(page: Page):
    try:
        selects = page.locator("select")
        for i in range(await selects.count()):
            select = selects.nth(i)
            if not await select.is_visible():
                continue
            options = await select.locator("option").all_inner_texts()
            choices = []
            for index, label in enumerate(options):
                match = re.search(r"\d+", label)
                if match:
                    choices.append((int(match.group()), index))
            if len(choices) >= 2:
                await select.select_option(index=max(choices)[1])
                await page.wait_for_timeout(PAGINATION_WAIT_MS)
                return True
    except Exception:
        pass

    for trigger_selector, option_selector in [
        (".ant-pagination-options .ant-select", ".ant-select-item-option"),
        ("mat-paginator mat-select", "mat-option"),
    ]:
        try:
            trigger = page.locator(trigger_selector).first
            if await trigger.count() and await trigger.is_visible():
                await trigger.click()
                await page.wait_for_timeout(400)
                options = page.locator(option_selector)
                if await options.count():
                    await options.last.click()
                    await page.wait_for_timeout(PAGINATION_WAIT_MS)
                    return True
        except Exception:
            pass
    return False


async def collect_cluster_links(page: Page):
    """Discover cluster details from anchors, clickable rows, and route changes.

    The Guardrail cluster table may use JavaScript row-click handlers rather
    than <a href="..."> links. This collector supports both patterns and
    saves a DOM diagnostic when it still cannot identify detail routes.
    """
    discovered = {}
    list_url = page.url
    list_path = urlparse(K8S_CLUSTER_LIST_URL).path.lower()

    def is_detail_url(candidate):
        try:
            parsed = urlparse(urljoin(BASE_URL, candidate))
            if parsed.netloc.lower() != urlparse(BASE_URL).netloc.lower():
                return False
            path = parsed.path.lower()
            if path == list_path or "k8s-cluster-list" in path:
                return False
            # Avoid requiring one exact route name: the app may use a generic
            # detail route and pass the cluster identifier in query params.
            has_id = any(parse_qs(parsed.query).get(k) for k in (
                "id", "clusterId", "cluster_id", "k8sClusterId", "k8s_cluster_id"
            ))
            route_hint = any(h in path for h in (
                "cluster", "k8s", "monitoring", "detail", "overview"
            ))
            return route_hint and (has_id or path != list_path)
        except Exception:
            return False

    def add(url, name="", row_text=""):
        full_url = urljoin(BASE_URL, url)
        if not is_detail_url(full_url):
            return
        label = normalize_text(name) or normalize_text(row_text)
        # Keep useful row text, but avoid storing huge table-wide text as a name.
        if len(label) > 180:
            label = label[:180]
        if not label:
            label = f"Kubernetes Cluster {len(discovered) + 1}"
        discovered[full_url] = {
            "name": label,
            "url": full_url,
            "id": extract_cluster_id(full_url),
        }

    async def scan_current_page():
        # 1) Standard links, including links whose route does not include the
        # exact hint from the original implementation.
        anchors = page.locator("a[href]")
        for i in range(await anchors.count()):
            link = anchors.nth(i)
            try:
                href = await link.get_attribute("href")
                if not href:
                    continue
                full_url = urljoin(BASE_URL, href)
                if is_detail_url(full_url):
                    label = normalize_text(await link.inner_text())
                    row_text = await link.evaluate("""el => {
                        const row = el.closest('tr, [role="row"], .ant-table-row, mat-row, li');
                        return (row || el).innerText || '';
                    }""")
                    add(full_url, label, row_text)
            except Exception:
                continue

        # 2) Some React/Ant tables use clickable rows/divs and no href at all.
        # Click each plausible cluster row and capture the resulting URL.
        if discovered:
            return
        row_selectors = [
            "tbody tr", "[role='row']", ".ant-table-row", "mat-row",
            "[class*='cluster'][class*='row']", "[class*='cursor-pointer']",
        ]
        seen_rows = set()
        for selector in row_selectors:
            rows = page.locator(selector)
            try:
                count = min(await rows.count(), 100)
            except Exception:
                continue
            for i in range(count):
                row = rows.nth(i)
                try:
                    if not await row.is_visible():
                        continue
                    text = normalize_text(await row.inner_text())
                    if not text or text.lower() in {"name", "cluster name", "no data"}:
                        continue
                    fingerprint = text[:200]
                    if fingerprint in seen_rows:
                        continue
                    seen_rows.add(fingerprint)

                    # Prefer hrefs/data attributes embedded anywhere in the row.
                    attrs = await row.evaluate("""el => {
                        const out = [];
                        const nodes = [el, ...el.querySelectorAll('*')];
                        for (const n of nodes) {
                          for (const a of ['href','data-href','data-url','routerlink','ng-reflect-router-link']) {
                            const v = n.getAttribute && n.getAttribute(a);
                            if (v) out.push({attr:a, value:v, text:(n.innerText||'').trim()});
                          }
                        }
                        return out;
                    }""")
                    for item in attrs:
                        val = item.get("value", "")
                        if val.startswith("/") and is_detail_url(urljoin(BASE_URL, val)):
                            add(val, item.get("text", ""), text)

                    if discovered:
                        continue

                    # Click only likely data rows, not headers/pagination.
                    before_url = page.url
                    await row.click(timeout=1800)
                    await page.wait_for_timeout(900)
                    after_url = page.url
                    if after_url != before_url and is_detail_url(after_url):
                        add(after_url, text, text)
                        # Return to list to continue scanning.
                        await page.go_back(wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT_MS)
                        await page.wait_for_timeout(900)
                    elif after_url != before_url:
                        # Route changed to another list/tab; return safely.
                        await page.goto(K8S_CLUSTER_LIST_URL, wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT_MS)
                        await page.wait_for_timeout(900)
                except Exception:
                    # A row may be non-interactive; try other rows/selectors.
                    if page.url != list_url and "k8s-cluster-list" not in page.url.lower():
                        try:
                            await page.goto(K8S_CLUSTER_LIST_URL, wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT_MS)
                            await page.wait_for_timeout(900)
                        except Exception:
                            pass
                    continue

    await try_set_max_page_size(page)
    if MANUAL_PAGE_SETUP:
        print("\nYou may adjust filters or rows-per-page in the browser.")
        await asyncio.to_thread(input, "Press Enter in this terminal to start collecting clusters... ")

    await scan_current_page()

    # Paginate, scanning after each change. Stop only if pagination is absent,
    # disabled, or the same page cannot be advanced after a retry.
    for _ in range(500):
        button = await find_next_button(page)
        if button is None:
            break
        before_urls = set(discovered)
        before_text = ""
        try:
            before_text = normalize_text(await page.locator("body").inner_text())[:5000]
            await button.click()
            await page.wait_for_timeout(PAGINATION_WAIT_MS)
            await scan_current_page()
            after_text = normalize_text(await page.locator("body").inner_text())[:5000]
            if set(discovered) == before_urls and after_text == before_text:
                await page.wait_for_timeout(PAGINATION_WAIT_MS)
                await scan_current_page()
                after_text = normalize_text(await page.locator("body").inner_text())[:5000]
                if set(discovered) == before_urls and after_text == before_text:
                    break
        except Exception:
            break
        print(f"  Found {len(discovered)} cluster detail route(s)...")

    # Fallback: list pages often expose the cluster table through an API and
    # render names as non-anchor React elements. Parse captured JSON payloads.
    api_found = {}
    for captured in list_api_payloads:
        walk_json_for_clusters(captured.get("body"), api_found)
    for item in api_found.values():
        discovered.setdefault(item["url"], item)

    if not discovered:
        # Save actionable diagnostics. Do not silently report a single hard-coded
        # cluster as if it represented the current account's full cluster set.
        os.makedirs(DEBUG_DIR, exist_ok=True)
        try:
            await page.screenshot(path=os.path.join(DEBUG_DIR, "cluster_list_not_detected.png"), full_page=True)
            with open(os.path.join(DEBUG_DIR, "cluster_list_dom_debug.txt"), "w", encoding="utf-8") as f:
                f.write(f"URL: {page.url}\nTITLE: {await page.title()}\n\n")
                f.write((await page.locator("body").inner_text())[:30000])
                f.write("\n\n--- ANCHORS ---\n")
                f.write(await page.locator("a[href]").evaluate_all(
                    "els => els.map(a => `${a.innerText.trim()} | ${a.getAttribute('href')}`).join('\\n')"
                ))
                f.write("\n\n--- API RESPONSES OBSERVED ON LIST PAGE ---\n")
                for item in list_api_payloads:
                    f.write(f"\nURL: {item['url']} | HTTP {item['status']}\n")
                    f.write(json.dumps(item.get("body"), ensure_ascii=False, default=str)[:5000])
                    f.write("\n")
        except Exception:
            pass

    result = list(discovered.values())
    print(f"\nKubernetes cluster detail routes found: {len(result)}")
    for index, cluster in enumerate(result, start=1):
        print(f"  {index}. {cluster['name']} | ID={cluster.get('id') or 'unknown'}")
        print(f"     {cluster['url']}")
    return result


async def open_monitoring_view(page: Page):
    """Click a visible Monitoring tab/button if the route did not select it."""
    if "tabindex=monitoring" in page.url.lower():
        return True

    candidates = [
        page.get_by_role("tab", name=re.compile("monitoring", re.I)),
        page.get_by_role("button", name=re.compile("monitoring", re.I)),
        page.get_by_text(re.compile(r"^\s*Monitoring\s*$", re.I)),
    ]
    for locator in candidates:
        try:
            for i in range(await locator.count()):
                element = locator.nth(i)
                if await element.is_visible():
                    await element.click()
                    await page.wait_for_timeout(2500)
                    return True
        except Exception:
            continue

    # Still capture APIs if this UI does not expose a distinct Monitoring tab.
    print("Note: Monitoring tab not confirmed; capturing APIs from the cluster page.")
    return False



async def discover_namespace_options(page: Page):
    """Open the Namespaces dropdown and return all visible option labels.

    Guardrail uses a custom dropdown in the Kubernetes Monitoring view. This
    helper supports common Ant Design, Angular Material, ARIA, and native
    select controls. It does not assume that an "All" option exists.
    """
    # Locate the control by its nearby "Namespaces" label first.
    trigger_candidates = [
        page.locator("label").filter(has_text=re.compile(r"^\s*Namespaces\s*$", re.I)),
        page.get_by_text(re.compile(r"^\s*Namespaces\s*$", re.I)),
    ]
    trigger = None
    for candidate in trigger_candidates:
        try:
            for i in range(await candidate.count()):
                el = candidate.nth(i)
                if await el.is_visible():
                    # The dropdown is usually the next select-like element in
                    # the same form/group/container.
                    parent = el.locator("xpath=..")
                    for selector in [
                        "select", "[role='combobox']", ".ant-select",
                        ".mat-mdc-select", ".mat-select", "[class*='select']",
                    ]:
                        control = parent.locator(selector).first
                        if await control.count() and await control.is_visible():
                            trigger = control
                            break
                    if trigger:
                        break
                    # Fallback to a nearby clickable element in the same
                    # ancestor, but avoid clicking the label itself.
                    for xp in ("xpath=../following-sibling::*[1]",
                               "xpath=../.."):
                        container = el.locator(xp)
                        for selector in [
                            "[role='combobox']", ".ant-select", "select",
                            ".mat-mdc-select", ".mat-select",
                        ]:
                            control = container.locator(selector).first
                            if await control.count() and await control.is_visible():
                                trigger = control
                                break
                        if trigger:
                            break
                if trigger:
                    break
        except Exception:
            continue
        if trigger:
            break

    # Last-resort: use the select-like control immediately following the
    # Namespaces text based on common Guardrail layout.
    if trigger is None:
        for selector in [
            ".ant-select", "[role='combobox']", "mat-select",
            ".mat-mdc-select", "select",
        ]:
            loc = page.locator(selector)
            try:
                count = await loc.count()
                for i in range(count):
                    el = loc.nth(i)
                    if await el.is_visible():
                        # Namespace is generally the second dropdown after Metrics.
                        # Prefer the second visible select-like control.
                        visible = []
                        for j in range(count):
                            x = loc.nth(j)
                            if await x.is_visible():
                                visible.append(x)
                        if len(visible) >= 2:
                            trigger = visible[1]
                        else:
                            trigger = el
                        break
            except Exception:
                pass
            if trigger:
                break

    if trigger is None:
        print("Namespace dropdown could not be located; processing current selection.")
        return []

    # Native select: gather labels and leave it open/unchanged.
    try:
        if await trigger.evaluate("(el) => el.tagName.toLowerCase() === 'select'"):
            return [normalize_text(x) for x in await trigger.locator("option").all_inner_texts()
                    if normalize_text(x)]
    except Exception:
        pass

    try:
        await trigger.click(timeout=2500)
        await page.wait_for_timeout(400)
    except Exception as exc:
        print(f"Could not open namespace dropdown: {exc}")
        return []

    option_selectors = [
        "[role='option']",
        ".ant-select-item-option",
        "mat-option",
        ".mat-mdc-option",
        "[role='listbox'] [role='option']",
        "li[role='option']",
    ]
    labels = []
    for selector in option_selectors:
        loc = page.locator(selector)
        try:
            count = await loc.count()
            found = []
            for i in range(count):
                el = loc.nth(i)
                if await el.is_visible():
                    text = normalize_text(await el.inner_text())
                    if text and text not in found:
                        found.append(text)
            if found:
                labels = found
                break
        except Exception:
            continue

    # Close dropdown by pressing Escape. Options are selected one by one later.
    try:
        await page.keyboard.press("Escape")
    except Exception:
        pass
    await page.wait_for_timeout(150)
    labels = [x for x in labels if x.lower() not in {"namespaces", "select", "no data"}]
    print(f"Namespace options detected: {len(labels)}")
    for label in labels:
        print(f"  - {label}")
    return labels


async def select_namespace(page: Page, namespace_name: str):
    """Select one namespace option; supports native and custom dropdowns."""
    # Find native select containing the requested option.
    selects = page.locator("select")
    try:
        for i in range(await selects.count()):
            sel = selects.nth(i)
            if not await sel.is_visible():
                continue
            options = await sel.locator("option").all_inner_texts()
            if any(normalize_text(x) == namespace_name for x in options):
                await sel.select_option(label=namespace_name)
                await page.wait_for_timeout(700)
                return True
    except Exception:
        pass

    # Reopen the namespace dropdown by locating its label and adjacent control.
    trigger = None
    labels = page.get_by_text(re.compile(r"^\s*Namespaces\s*$", re.I))
    try:
        for i in range(await labels.count()):
            lab = labels.nth(i)
            if not await lab.is_visible():
                continue
            for container_xpath in ("xpath=..", "xpath=../.."):
                container = lab.locator(container_xpath)
                for selector in [".ant-select", "[role='combobox']", ".mat-mdc-select",
                                 ".mat-select", "[class*='select']"]:
                    cand = container.locator(selector).first
                    if await cand.count() and await cand.is_visible():
                        trigger = cand
                        break
                if trigger:
                    break
            if trigger:
                break
    except Exception:
        pass

    if trigger is None:
        # Common layout fallback: namespace is the second select-like control.
        for selector in [".ant-select", "[role='combobox']", ".mat-mdc-select", ".mat-select"]:
            loc = page.locator(selector)
            try:
                visible = []
                for i in range(await loc.count()):
                    el = loc.nth(i)
                    if await el.is_visible():
                        visible.append(el)
                if len(visible) >= 2:
                    trigger = visible[1]
                    break
            except Exception:
                pass

    if trigger is None:
        return False

    try:
        await trigger.click(timeout=2500)
        await page.wait_for_timeout(300)
        options = page.locator(
            "[role='option'], [role='menuitem'], .ant-select-item-option, "
            "mat-option, .mat-mdc-option, [class*='option'], [class*='dropdown'] li, "
            "[class*='menu'] li"
        )
        for i in range(await options.count()):
            option = options.nth(i)
            try:
                if not await option.is_visible():
                    continue
                text = normalize_text(await option.inner_text())
                if text == namespace_name:
                    await option.click()
                    await page.wait_for_timeout(1200)
                    return True
            except Exception:
                continue

        # Guardrail's namespace menu may render plain divs without ARIA roles.
        # After opening the dropdown, click the exact visible text (e.g. "All").
        exact_text = page.get_by_text(namespace_name, exact=True)
        visible_matches = []
        for i in range(await exact_text.count()):
            item = exact_text.nth(i)
            try:
                if await item.is_visible():
                    visible_matches.append(item)
            except Exception:
                continue
        # The dropdown option is normally the last visible exact-text match.
        for item in reversed(visible_matches):
            try:
                await item.click(timeout=2000)
                await page.wait_for_timeout(1200)
                return True
            except Exception:
                continue
    except Exception:
        pass
    try:
        await page.keyboard.press("Escape")
    except Exception:
        pass
    return False


async def count_no_data_indicators(page: Page):
    try:
        text = await page.locator("body").inner_text()
        return len(re.findall(r"\bno\s+data\b", text, flags=re.I))
    except Exception:
        return 0


def save_debug_json(cluster, responses):
    os.makedirs(DEBUG_DIR, exist_ok=True)
    filename = safe_filename(f"{cluster['name']}_{cluster.get('id', '')}") + ".json"
    path = os.path.join(DEBUG_DIR, filename)
    serializable = []
    for item in responses:
        serializable.append({
            **{key: value for key, value in item.items() if key != "body"},
            "body": item.get("body"),
        })
    with open(path, "w", encoding="utf-8") as file:
        json.dump(serializable, file, indent=2, ensure_ascii=False, default=str)
    return path


async def process_cluster(page: Page, cluster):
    global active_cluster_label, captured_responses

    label = cluster["name"]
    active_cluster_label = label
    captured_responses = []

    print("\n" + "=" * 88)
    print(f"K8S CLUSTER: {label}")
    print(f"ID: {cluster.get('id') or 'unknown'}")
    print(f"URL: {cluster['url']}")
    print("=" * 88)

    try:
        await page.goto(cluster["url"], wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT_MS)
        await page.wait_for_timeout(2500)
        await open_monitoring_view(page)
        await page.wait_for_timeout(1200)

        # Discover every namespace and capture each namespace's monitoring
        # requests separately. If an explicit All option exists, use it once;
        # otherwise iterate each namespace because this dropdown is single-select.
        namespace_options = await discover_namespace_options(page)
        all_tokens = {"all", "all namespaces", "all namespace"}
        all_option = next((n for n in namespace_options if n.strip().lower() in all_tokens), None)

        # Guardrail's dropdown in the supplied screenshot has an explicit "All"
        # option. Prefer it so the graphs aggregate across every namespace.
        captured_responses = []
        active_namespace_label = all_option or "All"
        selected_all = False
        if all_option:
            selected_all = await select_namespace(page, all_option)
        else:
            # Even if option discovery could not read custom menu elements, try
            # selecting the exact visible "All" item directly.
            selected_all = await select_namespace(page, "All")
            if selected_all:
                active_namespace_label = "All"

        if selected_all:
            await page.wait_for_timeout(GRAPH_WAIT_MS)
            print("Selected namespace option: All (all namespaces)")
        else:
            print("WARNING: Could not select the 'All' namespace option.")
            print("Will attempt each detected namespace individually.")
            namespace_runs = [n for n in namespace_options if n.strip().lower() not in all_tokens]
            if not namespace_runs:
                namespace_runs = ["All"]
            for namespace_name in namespace_runs:
                active_namespace_label = namespace_name
                if namespace_name.strip().lower() not in all_tokens:
                    selected = await select_namespace(page, namespace_name)
                    if not selected:
                        print(f"WARNING: Could not select namespace '{namespace_name}'; skipping it.")
                        continue
                await page.wait_for_timeout(GRAPH_WAIT_MS)
                print(f"Captured namespace view: {namespace_name}")
    except Exception as exc:
        print(f"ERROR opening cluster page: {exc}")
        active_cluster_label = None
        return [{
            "Cluster": label, "Cluster ID": cluster.get("id", ""),
            "Cluster URL": cluster["url"], "Namespace": "", "Graph/API": "Cluster navigation",
            "HTTP Status": "", "Data Status": "NAVIGATION ERROR",
            "Reason": str(exc), "API": "", "Known K8s Endpoint": "No",
            "Frontend No Data Indicators": "", "Checked At": datetime.now().isoformat(timespec="seconds"),
        }]

    no_data_count = await count_no_data_indicators(page)

    # De-duplicate identical URL/status pairs while keeping the latest response.
    unique = {}
    for item in captured_responses:
        unique[(item["url"], item["status"])] = item
    responses = list(unique.values())

    debug_path = save_debug_json(cluster, responses)
    print(f"Captured API responses: {len(responses)}")
    print(f"Frontend 'No Data' indicators: {no_data_count}")
    print(f"Debug JSON: {debug_path}")

    results = []
    if not responses:
        results.append({
            "Cluster": label, "Cluster ID": cluster.get("id", ""),
            "Cluster URL": cluster["url"], "Namespace": active_namespace_label, "Graph/API": "No API response captured",
            "HTTP Status": "", "Data Status": "UNKNOWN",
            "Reason": "No /api/ XHR/fetch response captured on the cluster page",
            "API": "", "Known K8s Endpoint": "No",
            "Frontend No Data Indicators": no_data_count,
            "Checked At": datetime.now().isoformat(timespec="seconds"),
        })
    else:
        for item in responses:
            status, reason = analyze_response(item["status"], item["body"])
            graph_name = extract_graph_name(item["url"], item["body"])
            results.append({
                "Cluster": label,
                "Cluster ID": cluster.get("id", ""),
                "Cluster URL": cluster["url"],
                "Namespace": active_namespace_label,
                "Graph/API": graph_name,
                "HTTP Status": item["status"],
                "Data Status": status,
                "Reason": reason,
                "API": item["url"],
                "Known K8s Endpoint": "Yes" if item["known_pattern"] else "No",
                "Frontend No Data Indicators": no_data_count,
                "Checked At": item["timestamp"],
            })
            print(f"{graph_name[:28]:28} | HTTP {item['status']:<3} | {status:15} | {reason}")

    if no_data_count:
        os.makedirs(DEBUG_DIR, exist_ok=True)
        screenshot_path = os.path.join(
            DEBUG_DIR, safe_filename(f"{label}_{cluster.get('id', '')}_NO_DATA") + ".png"
        )
        try:
            await page.screenshot(path=screenshot_path, full_page=True)
            print(f"No-data screenshot: {screenshot_path}")
        except Exception as exc:
            print(f"Could not save screenshot: {exc}")

    active_cluster_label = None
    return results


def write_csv(results):
    columns = [
        "Account", "Cluster", "Cluster ID", "Cluster URL", "Namespace", "Graph/API", "HTTP Status",
        "Data Status", "Reason", "API", "Known K8s Endpoint",
        "Frontend No Data Indicators", "Checked At",
    ]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)


async def _visible_text(locator):
    try:
        if await locator.is_visible():
            return normalize_text(await locator.inner_text())
    except Exception:
        pass
    return ""


async def _open_account_selector(page: Page) -> bool:
    """Explicitly open Guardrail's header account picker."""
    # In the supplied screenshot the picker is a header input labelled
    # "Select Account". Try exact placeholder first, then visible text/container.
    selectors = [
        "input[placeholder='Select Account']",
        "input[placeholder*='Select Account' i]",
        "input[aria-label*='Select Account' i]",
    ]
    for selector in selectors:
        loc = page.locator(selector).first
        try:
            if await loc.count() and await loc.is_visible():
                await loc.click(timeout=4000)
                await page.wait_for_timeout(700)
                print("Opened Guardrail account picker using header input.")
                return True
        except Exception as exc:
            print(f"Account picker input attempt failed ({selector}): {exc}")

    # Fallback: click visible header text/button that opens the account selector.
    for locator in [
        page.get_by_text(re.compile(r"^\s*Select Account\s*$", re.I)).last,
        page.get_by_role("button", name=re.compile(r"account", re.I)).last,
    ]:
        try:
            if await locator.count() and await locator.is_visible():
                await locator.click(timeout=3000)
                await page.wait_for_timeout(700)
                # Verify that a search input or account-like menu is visible.
                if await page.locator("input[placeholder*='Select Account' i], [role='option'], [role='listbox']").count():
                    print("Opened Guardrail account picker using header control.")
                    return True
        except Exception:
            continue

    print("ERROR: Could not open the Guardrail account picker. No account sweep will be attempted.")
    return False


async def discover_account_names(page: Page):
    """Open the real account picker and read account rows from its visible menu.

    Guardrail's account picker is a custom, scrollable menu. Avoid scanning all
    page text (which accidentally treats navigation labels as accounts).
    """
    if not await _open_account_selector(page):
        return []

    names = []
    previous_signature = None
    stagnant_rounds = 0
    for _ in range(50):
        # Read actual option/list rows first; fall back to elements in the popup.
        candidates = []
        for selector in [
            "[role='option']", "[role='listbox'] > *", "[role='listbox'] [role]",
            ".ant-select-item-option", ".mat-mdc-option", "mat-option",
            "[class*='account-option']", "[class*='accountOption']",
        ]:
            loc = page.locator(selector)
            try:
                for i in range(min(await loc.count(), 300)):
                    el = loc.nth(i)
                    if await el.is_visible():
                        txt = normalize_text(await el.inner_text())
                        if txt and len(txt) <= 100:
                            candidates.append(txt)
            except Exception:
                continue

        # Screenshot-confirmed fallback: the account picker shows one row per
        # account with a star icon and a label, under the Select Account input.
        if not candidates:
            try:
                candidates = await page.evaluate("""() => {
                  const input = document.querySelector("input[placeholder*='Select Account' i], input[aria-label*='Select Account' i]");
                  if (!input) return [];
                  const ir = input.getBoundingClientRect();
                  const visible = e => { const r=e.getBoundingClientRect(), s=getComputedStyle(e); return r.width>0 && r.height>0 && s.visibility!=='hidden' && s.display!=='none'; };
                  const nodes = [...document.querySelectorAll('div,li,button,a,[role]')].filter(visible);
                  const rows = nodes.filter(e => {
                    const r=e.getBoundingClientRect();
                    const t=(e.innerText||'').trim();
                    return r.top >= ir.bottom-2 && r.top < innerHeight && r.left >= ir.left-30 &&
                      r.width>100 && r.height>=24 && r.height<=75 && t && t.length<=100 &&
                      !/^(Select Account|Search|Clear|Close)$/i.test(t) && e.children.length<=4;
                  }).sort((a,b)=>a.getBoundingClientRect().top-b.getBoundingClientRect().top);
                  const out=[];
                  for (const e of rows) { const t=(e.innerText||'').trim(); if(t && !out.includes(t)) out.push(t); }
                  return out;
                }""")
            except Exception:
                candidates = []

        for raw in candidates:
            # Some nested option selectors return multiple lines/icons; retain
            # only the first line as the visible account label.
            label = normalize_text(raw.splitlines()[0] if raw.splitlines() else raw)
            low = label.lower()
            if not label or low in {
                "select account", "search", "clear", "close", "monitoring and automation",
                "account", "all", "what's new", "view release log", "latest updates",
            }:
                continue
            if any(term in low for term in ("log out", "available services", "manage access", "view release log")):
                continue
            if label not in names:
                names.append(label)

        signature = tuple(names)
        if signature == previous_signature:
            stagnant_rounds += 1
        else:
            stagnant_rounds = 0
            previous_signature = signature
        if stagnant_rounds >= 3:
            break

        # Scroll the account popup, not the whole page. The screenshot shows a
        # narrow vertical scrollbar beside the account rows.
        try:
            await page.evaluate("""() => {
              const input = document.querySelector("input[placeholder*='Select Account' i], input[aria-label*='Select Account' i]");
              if (!input) return;
              const ir=input.getBoundingClientRect();
              const candidates=[...document.querySelectorAll('div,ul,section')].filter(e=>{
                const r=e.getBoundingClientRect(),s=getComputedStyle(e);
                return r.left>=ir.left-30 && r.left<ir.right+80 && r.top>=ir.bottom-2 &&
                  r.width>150 && r.height>80 && r.height<innerHeight &&
                  (s.overflowY==='auto'||s.overflowY==='scroll') && e.scrollHeight>e.clientHeight+10;
              }).sort((a,b)=>a.getBoundingClientRect().top-b.getBoundingClientRect().top);
              if(candidates.length){const e=candidates[0]; e.scrollTop=Math.min(e.scrollTop+Math.max(140,e.clientHeight-30),e.scrollHeight);}
            }""")
            await page.wait_for_timeout(250)
        except Exception:
            break

    print(f"Account options discovered: {len(names)}")
    for name in names:
        print(f"  - {name}")
    if not names:
        os.makedirs(DEBUG_DIR, exist_ok=True)
        try:
            await page.screenshot(path=os.path.join(DEBUG_DIR, "account_picker_not_detected.png"), full_page=True)
            with open(os.path.join(DEBUG_DIR, "account_picker_dom_debug.txt"), "w", encoding="utf-8") as f:
                f.write(f"URL: {page.url}\nTITLE: {await page.title()}\n")
                f.write((await page.locator('body').inner_text())[:20000])
                f.write("\n\nINPUTS:\n")
                f.write(await page.locator('input').evaluate_all("els => els.map(e => `${e.placeholder} | ${e.getAttribute('aria-label')} | ${e.outerHTML}`).join('\\n')"))
        except Exception:
            pass
    try:
        await page.keyboard.press("Escape")
    except Exception:
        pass
    return names


async def select_account(page: Page, account_name: str) -> bool:
    """Open the picker, filter by account label, then click its visible option."""
    if not await _open_account_selector(page):
        return False

    search = page.locator("input[placeholder*='Select Account' i], input[aria-label*='Select Account' i]").first
    try:
        if await search.count() and await search.is_visible():
            await search.fill(account_name, timeout=2500)
            await page.wait_for_timeout(500)
    except Exception:
        pass

    # Prefer a visible menu row whose text contains the exact account label.
    for selector in ["[role='option']", "[role='listbox'] *", "button", "li", "div"]:
        loc = page.locator(selector)
        try:
            for i in range(min(await loc.count(), 500)):
                el = loc.nth(i)
                if not await el.is_visible():
                    continue
                txt = normalize_text(await el.inner_text())
                if txt == account_name or (len(txt) <= 100 and account_name.lower() in txt.lower()):
                    await el.click(timeout=2500)
                    await page.wait_for_timeout(1800)
                    print(f"Selected account: {account_name}")
                    return True
        except Exception:
            continue

    # Search-filtered menus sometimes expose the account as plain text only.
    try:
        option = page.get_by_text(re.compile(re.escape(account_name), re.I)).last
        if await option.count() and await option.is_visible():
            await option.click(timeout=2500)
            await page.wait_for_timeout(1800)
            print(f"Selected account: {account_name}")
            return True
    except Exception:
        pass

    print(f"ERROR: Account '{account_name}' was not selected; skipping it to avoid reporting the wrong account.")
    try:
        await page.keyboard.press("Escape")
    except Exception:
        pass
    return False


async def process_current_account(page: Page, account_name: str):
    """Discover and validate all clusters for the currently selected account."""
    global active_account_label
    active_account_label = account_name
    list_api_payloads.clear()
    print("\n" + "#" * 88)
    print(f"ACCOUNT: {account_name}")
    print("#" * 88)
    await page.goto(K8S_CLUSTER_LIST_URL, wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT_MS)
    await page.wait_for_timeout(3500)
    clusters = await collect_cluster_links(page)
    account_results = []
    if not clusters:
        print(f"No clusters discovered for account '{account_name}'. Check account/list API diagnostics.")
        return account_results, 0
    print(f"Clusters discovered for {account_name}: {len(clusters)}")
    for index, cluster in enumerate(clusters, start=1):
        print(f"\nAccount {account_name} | cluster {index}/{len(clusters)}")
        rows = await process_cluster(page, cluster)
        for row in rows:
            row["Account"] = account_name
        account_results.extend(rows)
    return account_results, len(clusters)


async def main():
    async with async_playwright() as playwright:
        print("Starting Guardrail Kubernetes Cluster Graph Validator (all accounts)...")
        context = await playwright.chromium.launch_persistent_context(
            PROFILE_DIR,
            headless=False,
            no_viewport=True,
            args=["--start-maximized"],
            accept_downloads=True,
        )
        try:
            page = context.pages[0] if context.pages else await context.new_page()
            page.on("response", response_listener)
            page.on("response", list_response_listener)
            await ensure_authenticated(page)

            # Open a stable dashboard page before reading the account selector.
            await page.goto(DASHBOARD_URL, wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT_MS)
            await page.wait_for_timeout(1200)
            print("Opening the top-header Select Account picker...")
            account_names = await discover_account_names(page)

            all_results = []
            total_clusters = 0
            if not account_names:
                print("STOPPING: account picker was not opened/read. No cluster scan will run under an unverified account.")
                print(f"Inspect {DEBUG_DIR}/account_picker_not_detected.png and account_picker_dom_debug.txt")
            else:
                processed_accounts = set()
                for account_name in account_names:
                    if account_name in processed_accounts:
                        continue
                    if not await select_account(page, account_name):
                        continue
                    processed_accounts.add(account_name)
                    rows, count = await process_current_account(page, account_name)
                    all_results.extend(rows)
                    total_clusters += count

            write_csv(all_results)
            no_data = [row for row in all_results if row.get("Data Status") == "NO DATA"]
            errors = [row for row in all_results if row.get("Data Status") == "API ERROR"]
            available = [row for row in all_results if row.get("Data Status") == "DATA AVAILABLE"]
            unknown = [row for row in all_results if row.get("Data Status") == "UNKNOWN"]
            print("\n" + "=" * 88)
            print("GUARDRAIL KUBERNETES CLUSTER VALIDATION — ALL ACCOUNTS")
            print("=" * 88)
            print(f"Accounts attempted     : {len(account_names) if account_names else 1}")
            print(f"Clusters checked       : {total_clusters}")
            print(f"Graph/API records      : {len(all_results)}")
            print(f"Data available         : {len(available)}")
            print(f"No data                : {len(no_data)}")
            print(f"API errors (HTTP >=400): {len(errors)}")
            print(f"Unknown                : {len(unknown)}")
            print(f"CSV report             : {OUTPUT_CSV}")
            print(f"Debug JSON/screenshots : {DEBUG_DIR}/")
            print("=" * 88)
        finally:
            await context.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as exc:
        print(f"\nFATAL ERROR: {exc}")
