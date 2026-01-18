#!/usr/bin/env python3
"""
CVE-2025-55182 (React2Shell) 내부 시스템 취약점 확인 스크립트
용도: 내부 보안 점검용 (인가된 시스템만 대상으로 사용)
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# SSL 경고 무시 (내부망 자체서명 인증서 대응)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 취약 버전 정의
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

# RSC 탐지용 헤더/패턴
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
    ]
}


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
    """버전이 취약한지 확인"""
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


def check_rsc_endpoint(url, timeout=10):
    """RSC 엔드포인트 존재 여부 확인"""
    results = {
        "url": url,
        "rsc_detected": False,
        "version_info": {},
        "indicators": [],
        "status": "unknown",
        "error": None
    }
    
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
        
        # 2. RSC 헤더로 요청 시도
        rsc_headers = {
            "RSC": "1",
            "Next-Router-State-Tree": "%5B%22%22%5D",
            "User-Agent": "Mozilla/5.0 (Internal Security Scanner)"
        }
        
        rsc_resp = requests.get(
            url,
            headers=rsc_headers,
            timeout=timeout,
            verify=False
        )
        
        # Content-Type 확인
        content_type = rsc_resp.headers.get("Content-Type", "")
        for ct in RSC_INDICATORS["content_types"]:
            if ct in content_type:
                results["rsc_detected"] = True
                results["indicators"].append(f"RSC Content-Type: {content_type}")
        
        # 응답 패턴 확인
        for pattern in RSC_INDICATORS["response_patterns"]:
            if re.search(pattern, rsc_resp.text[:100]):
                results["rsc_detected"] = True
                results["indicators"].append("RSC Flight protocol response detected")
                break
        
        # 3. /_next/static 에서 빌드 정보 추출 시도
        build_manifest_url = url.rstrip('/') + "/_next/static/chunks/webpack.js"
        try:
            manifest_resp = requests.get(
                build_manifest_url, 
                timeout=5, 
                verify=False
            )
            # 버전 패턴 매칭
            version_match = re.search(r'next[/\\](\d+\.\d+\.\d+)', manifest_resp.text)
            if version_match:
                next_version = version_match.group(1)
                results["version_info"]["next"] = next_version
                if is_version_vulnerable(next_version, "next"):
                    results["indicators"].append(f"VULNERABLE Next.js version: {next_version}")
        except:
            pass
        
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


def scan_targets(targets, max_workers=10):
    """여러 대상 동시 스캔"""
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(check_rsc_endpoint, url): url 
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


def main():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  CVE-2025-55182 (React2Shell) 내부 시스템 취약점 스캐너      ║
║  용도: 인가된 내부 보안 점검 전용                            ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # 대상 URL 입력
    if len(sys.argv) > 1:
        targets = []
        for arg in sys.argv[1:]:
            # URL인지 파일인지 판단
            if arg.startswith(('http://', 'https://')):
                # URL 직접 입력
                targets.append(arg)
            elif os.path.isfile(arg):
                # 파일에서 읽기
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
                # http 없는 URL로 간주
                targets.append('https://' + arg)
    else:
        print("대상 URL을 입력하세요 (한 줄에 하나, 빈 줄 입력 시 스캔 시작):")
        targets = []
        while True:
            try:
                line = input()
                if line.strip():
                    # URL 형식 보정
                    url = line.strip()
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    targets.append(url)
                else:
                    break
            except EOFError:
                break
    
    if not targets:
        print("❌ 스캔할 대상이 없습니다.")
        sys.exit(1)
    
    print(f"\n🔍 {len(targets)}개 대상 스캔 시작...\n")
    
    # 스캔 실행
    results = scan_targets(targets)
    
    # 보고서 생성
    output_file = f"react2shell_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    generate_report(results, output_file)
    
    # 취약 시스템 있으면 종료 코드 1
    vulnerable_count = sum(1 for r in results if r["status"] == "VULNERABLE")
    sys.exit(1 if vulnerable_count > 0 else 0)


if __name__ == "__main__":
    main()