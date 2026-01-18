#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RSC (React Server Components) 탐지 스캐너 v1.0
용도: 외부에서 RSC 사용 여부 탐지 (Next.js, Waku, TanStack 등 모든 RSC 구현체)

사용법:
    python rsc_detector.py <url>
    python rsc_detector.py <url_list.txt>
    python rsc_detector.py <url_list.txt> -o result.json -t 20

탐지 방법:
    1. RSC 헤더 요청 (Accept: text/x-component, RSC: 1)
    2. Content-Type: text/x-component 응답 확인
    3. Flight 프로토콜 패턴 매칭
    4. Vary: rsc 헤더 확인
    5. 프레임워크별 fingerprint
"""

import argparse
import json
import re
import sys
import os
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("requests 라이브러리가 필요합니다: pip install requests")
    sys.exit(1)

# 버전 정보
SCANNER_VERSION = "1.0"

# 타임아웃 설정
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 10

# RSC 관련 패턴
FLIGHT_PATTERNS = [
    r'^\d+:',                    # 0:{"... 1:... 형태
    r'E\{"digest"',              # E{"digest":"..."} 에러 응답
    r'\$@\d+',                   # $@1 참조 패턴
    r'\$L\d+',                   # $L1 lazy 참조
    r'"([^"]+)":\s*"\$',         # Flight 직렬화 패턴
]

# 프레임워크별 fingerprint
FRAMEWORK_SIGNATURES = {
    'nextjs': {
        'headers': ['x-powered-by'],
        'header_values': {'x-powered-by': 'Next.js'},
        'paths': ['/_next/', '/_next/static/'],
        'indicators': ['__next', 'Next.js'],
    },
    'waku': {
        'headers': [],
        'paths': ['/_waku/', '/RSC/'],
        'indicators': ['waku'],
    },
    'tanstack': {
        'headers': [],
        'paths': ['/_server/'],
        'indicators': ['tanstack', 'TanStack'],
    },
    'hydrogen': {
        'headers': ['x-shopify'],
        'paths': [],
        'indicators': ['shopify', 'hydrogen'],
    },
}


class Colors:
    """콘솔 색상"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    
    @staticmethod
    def init():
        if sys.platform == 'win32':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                Colors.RED = Colors.GREEN = Colors.YELLOW = ''
                Colors.CYAN = Colors.MAGENTA = Colors.RESET = ''


def create_session() -> requests.Session:
    """재시도 로직이 포함된 세션 생성"""
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def normalize_url(url: str) -> str:
    """URL 정규화"""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def check_rsc_headers(session: requests.Session, url: str, timeout: int) -> Dict:
    """RSC 헤더로 요청하여 탐지"""
    result = {
        'rsc_header_request': False,
        'content_type_rsc': False,
        'vary_rsc': False,
        'flight_pattern': False,
        'raw_response': None,
    }
    
    # RSC 전용 헤더로 요청
    headers = {
        'Accept': 'text/x-component',
        'RSC': '1',
        'Next-Router-State-Tree': '%5B%22%22%5D',  # Next.js 호환
        'User-Agent': 'Mozilla/5.0 (compatible; RSCScanner/1.0)',
    }
    
    try:
        resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        
        # Content-Type 확인
        content_type = resp.headers.get('Content-Type', '')
        if 'text/x-component' in content_type:
            result['rsc_header_request'] = True
            result['content_type_rsc'] = True
        
        # Vary 헤더 확인
        vary = resp.headers.get('Vary', '')
        if 'rsc' in vary.lower():
            result['vary_rsc'] = True
        
        # Flight 프로토콜 패턴 확인
        for pattern in FLIGHT_PATTERNS:
            if re.search(pattern, resp.text[:2000]):
                result['flight_pattern'] = True
                break
        
        result['raw_response'] = resp.text[:500] if result['flight_pattern'] else None
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def check_nextjs_safe_check(session: requests.Session, url: str, timeout: int) -> Dict:
    """Next.js Safe-Check (기존 방식)"""
    result = {
        'safe_check': False,
        'digest_pattern': False,
    }
    
    try:
        # Next-Action 헤더로 POST 요청
        headers = {
            'Content-Type': 'multipart/form-data; boundary=----formdata',
            'Next-Action': 'a' * 40,
            'User-Agent': 'Mozilla/5.0 (compatible; RSCScanner/1.0)',
        }
        
        payload = (
            '------formdata\r\n'
            'Content-Disposition: form-data; name="1_$ACTION_ID_a"\r\n\r\n'
            '["$1:aa:aa"]\r\n'
            '------formdata--\r\n'
        )
        
        resp = session.post(url, headers=headers, data=payload, timeout=timeout, allow_redirects=True)
        
        if resp.status_code == 500 and 'E{"digest"' in resp.text:
            result['safe_check'] = True
            result['digest_pattern'] = True
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def check_framework_fingerprint(session: requests.Session, url: str, timeout: int) -> Dict:
    """프레임워크별 fingerprint 탐지"""
    result = {
        'framework': None,
        'indicators': [],
    }
    
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        
        for framework, sigs in FRAMEWORK_SIGNATURES.items():
            indicators = []
            
            # 헤더 값 확인
            for header, expected in sigs.get('header_values', {}).items():
                if expected.lower() in headers_lower.get(header, '').lower():
                    indicators.append(f"header:{header}={expected}")
            
            # 응답 본문에서 indicator 확인
            for indicator in sigs.get('indicators', []):
                if indicator.lower() in resp.text.lower():
                    indicators.append(f"body:{indicator}")
            
            if indicators:
                result['framework'] = framework
                result['indicators'] = indicators
                break
        
        # 경로 기반 탐지
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for framework, sigs in FRAMEWORK_SIGNATURES.items():
            for path in sigs.get('paths', []):
                try:
                    path_resp = session.get(urljoin(base_url, path), timeout=timeout/2)
                    if path_resp.status_code != 404:
                        if not result['framework']:
                            result['framework'] = framework
                        result['indicators'].append(f"path:{path}")
                except:
                    pass
                    
    except Exception as e:
        result['error'] = str(e)
    
    return result


def scan_url(url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict:
    """단일 URL 스캔"""
    url = normalize_url(url)
    session = create_session()
    
    result = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'rsc_detected': False,
        'framework': None,
        'detection_methods': [],
        'details': {},
    }
    
    try:
        # 1. RSC 헤더 요청
        rsc_check = check_rsc_headers(session, url, timeout)
        result['details']['rsc_headers'] = rsc_check
        
        if rsc_check.get('content_type_rsc') or rsc_check.get('flight_pattern'):
            result['rsc_detected'] = True
            result['detection_methods'].append('rsc_header_request')
        
        if rsc_check.get('vary_rsc'):
            result['rsc_detected'] = True
            result['detection_methods'].append('vary_rsc')
        
        # 2. Next.js Safe-Check
        safe_check = check_nextjs_safe_check(session, url, timeout)
        result['details']['safe_check'] = safe_check
        
        if safe_check.get('safe_check'):
            result['rsc_detected'] = True
            result['detection_methods'].append('nextjs_safe_check')
        
        # 3. 프레임워크 fingerprint
        fingerprint = check_framework_fingerprint(session, url, timeout)
        result['details']['fingerprint'] = fingerprint
        
        if fingerprint.get('framework'):
            result['framework'] = fingerprint['framework']
            result['detection_methods'].append(f"fingerprint:{fingerprint['framework']}")
        
        # 최종 상태 결정
        if result['rsc_detected']:
            result['status'] = 'RSC_DETECTED'
        elif result['framework']:
            result['status'] = 'FRAMEWORK_DETECTED'
        else:
            result['status'] = 'NOT_DETECTED'
            
    except Exception as e:
        result['status'] = 'ERROR'
        result['error'] = str(e)
    
    return result


def print_result(result: Dict):
    """결과 출력"""
    c = Colors
    url = result['url']
    status = result.get('status', 'UNKNOWN')
    
    if status == 'RSC_DETECTED':
        icon = f"{c.RED}🔴"
        status_text = f"RSC 탐지됨{c.RESET}"
    elif status == 'FRAMEWORK_DETECTED':
        icon = f"{c.YELLOW}🟡"
        status_text = f"프레임워크 감지{c.RESET}"
    elif status == 'ERROR':
        icon = f"{c.MAGENTA}⚠️"
        status_text = f"에러{c.RESET}"
    else:
        icon = f"{c.GREEN}🟢"
        status_text = f"미탐지{c.RESET}"
    
    print(f"{icon} {c.CYAN}{url}{c.RESET}")
    print(f"   상태: {status_text}")
    
    if result.get('framework'):
        print(f"   프레임워크: {result['framework']}")
    
    if result.get('detection_methods'):
        print(f"   탐지 방법: {', '.join(result['detection_methods'])}")
    
    if result.get('error'):
        print(f"   {c.RED}에러: {result['error']}{c.RESET}")
    
    print()


def load_urls(input_path: str) -> List[str]:
    """URL 목록 로드"""
    if os.path.isfile(input_path):
        with open(input_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        return [input_path]


def main():
    Colors.init()
    
    parser = argparse.ArgumentParser(
        description='RSC (React Server Components) 탐지 스캐너',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input', help='스캔할 URL 또는 URL 목록 파일')
    parser.add_argument('-o', '--output', help='JSON 결과 파일 경로')
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS, help=f'스레드 수 (기본값: {DEFAULT_THREADS})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'타임아웃 초 (기본값: {DEFAULT_TIMEOUT})')
    parser.add_argument('-q', '--quiet', action='store_true', help='간략 출력')
    
    args = parser.parse_args()
    
    print()
    print("=" * 60)
    print(f"  RSC (React Server Components) 탐지 스캐너 v{SCANNER_VERSION}")
    print("  대상: Next.js, Waku, TanStack Start, Hydrogen 등")
    print("=" * 60)
    print()
    
    urls = load_urls(args.input)
    print(f"스캔 대상: {len(urls)}개 URL")
    print("-" * 60)
    
    results = []
    rsc_count = 0
    
    if len(urls) == 1:
        # 단일 URL
        result = scan_url(urls[0], args.timeout)
        results.append(result)
        if not args.quiet:
            print()
            print_result(result)
        if result.get('rsc_detected'):
            rsc_count += 1
    else:
        # 멀티 스레드 스캔
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_url = {
                executor.submit(scan_url, url, args.timeout): url 
                for url in urls
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                result = future.result()
                results.append(result)
                
                if not args.quiet:
                    print_result(result)
                
                if result.get('rsc_detected'):
                    rsc_count += 1
    
    # 요약
    print("=" * 60)
    print("📊 스캔 결과 요약")
    print("=" * 60)
    print(f"  총 스캔: {len(results)}개")
    print(f"  RSC 탐지: {Colors.RED if rsc_count > 0 else Colors.GREEN}{rsc_count}개{Colors.RESET}")
    print()
    
    # JSON 저장
    if args.output:
        output_data = {
            'scan_info': {
                'scan_time': datetime.now().isoformat(),
                'scanner_version': SCANNER_VERSION,
                'total_urls': len(results),
                'rsc_detected_count': rsc_count,
            },
            'results': results
        }
        
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        
        print(f"📄 결과 저장됨: {args.output}")
    
    # 자동 저장 (output 미지정 시)
    if not args.output:
        exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        auto_output = os.path.join(exe_dir, f"rsc_scan_result_{timestamp}.json")
        
        output_data = {
            'scan_info': {
                'scan_time': datetime.now().isoformat(),
                'scanner_version': SCANNER_VERSION,
                'total_urls': len(results),
                'rsc_detected_count': rsc_count,
            },
            'results': results
        }
        
        with open(auto_output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        
        print(f"📄 결과 저장됨: {auto_output}")
    
    print()
    sys.exit(1 if rsc_count > 0 else 0)


if __name__ == '__main__':
    main()