#!/usr/bin/env python3
"""
CVE-2025-55182 (React2Shell) 로컬 프로젝트 취약점 확인
용도: 내부 프로젝트 소스코드/package.json 기반 취약 버전 탐지
"""

import os
import json
import re
import sys
from pathlib import Path

# 취약 버전 정의
VULNERABLE = {
    "react": {"min": (19, 0, 0), "fixed": (19, 0, 1)},
    "react-dom": {"min": (19, 0, 0), "fixed": (19, 0, 1)},
    "react-server": {"min": (19, 0, 0), "fixed": (19, 0, 1)},
    "next": {
        "ranges": [
            {"min": (15, 0, 0), "fixed": (15, 1, 4)},
            {"min": (16, 0, 0), "fixed": (16, 0, 7)}
        ]
    }
}


def parse_version(ver_str):
    """버전 문자열 파싱"""
    if not ver_str:
        return None
    # ^, ~, >=, 등 제거
    clean = re.sub(r'^[\^~>=<]+', '', str(ver_str))
    clean = re.split(r'[-+]', clean)[0]
    try:
        parts = clean.split('.')
        return tuple(int(p) for p in parts[:3])
    except:
        return None


def check_version(pkg_name, version):
    """패키지 버전이 취약한지 확인"""
    v = parse_version(version)
    if not v:
        return None, "버전 파싱 불가"
    
    if pkg_name == "next":
        for r in VULNERABLE["next"]["ranges"]:
            if r["min"] <= v < r["fixed"]:
                return True, f"취약 (패치 버전: {'.'.join(map(str, r['fixed']))})"
        if v >= VULNERABLE["next"]["ranges"][-1]["fixed"]:
            return False, "패치됨"
        return False, "취약 범위 아님"
    
    elif pkg_name in VULNERABLE:
        info = VULNERABLE[pkg_name]
        if info["min"] <= v < info["fixed"]:
            return True, f"취약 (패치 버전: {'.'.join(map(str, info['fixed']))})"
        elif v >= info["fixed"]:
            return False, "패치됨"
    
    return None, "확인 대상 아님"


def scan_package_json(file_path):
    """package.json 파일 분석"""
    results = {
        "file": str(file_path),
        "vulnerable": [],
        "safe": [],
        "warnings": []
    }
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        results["warnings"].append(f"파일 읽기 실패: {e}")
        return results
    
    # dependencies, devDependencies 모두 확인
    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))
    
    target_packages = ["react", "react-dom", "react-server", "next"]
    
    for pkg in target_packages:
        if pkg in all_deps:
            version = all_deps[pkg]
            is_vuln, message = check_version(pkg, version)
            
            entry = {"package": pkg, "version": version, "message": message}
            
            if is_vuln is True:
                results["vulnerable"].append(entry)
            elif is_vuln is False:
                results["safe"].append(entry)
            else:
                results["warnings"].append(entry)
    
    return results


def scan_directory(root_path, recursive=True):
    """디렉토리에서 package.json 파일들 스캔"""
    root = Path(root_path)
    all_results = []
    
    if recursive:
        package_files = root.rglob("package.json")
    else:
        package_files = root.glob("package.json")
    
    for pf in package_files:
        # node_modules 제외
        if "node_modules" in str(pf):
            continue
        
        result = scan_package_json(pf)
        all_results.append(result)
    
    return all_results


def scan_lockfile(file_path):
    """package-lock.json 또는 yarn.lock 분석 (실제 설치 버전)"""
    results = {
        "file": str(file_path),
        "vulnerable": [],
        "safe": []
    }
    
    file_path = Path(file_path)
    
    if file_path.name == "package-lock.json":
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            packages = data.get("packages", {})
            # npm v7+ 형식
            for pkg_path, info in packages.items():
                pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
                if pkg_name in ["react", "react-dom", "react-server", "next"]:
                    version = info.get("version", "")
                    is_vuln, message = check_version(pkg_name, version)
                    entry = {"package": pkg_name, "version": version, "message": message}
                    if is_vuln:
                        results["vulnerable"].append(entry)
                    elif is_vuln is False:
                        results["safe"].append(entry)
                        
        except Exception as e:
            results["error"] = str(e)
    
    return results


def print_report(all_results):
    """결과 출력"""
    print("\n" + "="*60)
    print("CVE-2025-55182 (React2Shell) 로컬 프로젝트 스캔 결과")
    print("="*60)
    
    total_vulnerable = 0
    vulnerable_projects = []
    
    for result in all_results:
        if result["vulnerable"]:
            total_vulnerable += len(result["vulnerable"])
            vulnerable_projects.append(result)
    
    if vulnerable_projects:
        print(f"\n🔴 취약한 프로젝트 발견: {len(vulnerable_projects)}개\n")
        
        for proj in vulnerable_projects:
            print(f"📁 {proj['file']}")
            for vuln in proj["vulnerable"]:
                print(f"   🔴 {vuln['package']}@{vuln['version']} - {vuln['message']}")
            print()
        
        print("\n⚠️  권장 조치:")
        print("   1. React: npm install react@19.0.1 react-dom@19.0.1")
        print("   2. Next.js 15.x: npm install next@15.1.4")
        print("   3. Next.js 16.x: npm install next@16.0.7")
        print("   4. 패치 후 재배포 필요")
        
    else:
        print("\n✅ 취약한 프로젝트가 발견되지 않았습니다.")
    
    # 안전한 프로젝트
    safe_count = sum(len(r["safe"]) for r in all_results)
    if safe_count:
        print(f"\n🟢 패치된 패키지: {safe_count}개")
    
    return len(vulnerable_projects)


def main():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  CVE-2025-55182 로컬 프로젝트 취약점 스캐너                  ║
║  package.json / package-lock.json 기반 버전 확인             ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("스캔할 디렉토리 경로 (기본: 현재 디렉토리): ").strip() or "."
    
    target_path = Path(target)
    
    if not target_path.exists():
        print(f"❌ 경로가 존재하지 않습니다: {target}")
        sys.exit(1)
    
    print(f"\n🔍 스캔 대상: {target_path.absolute()}\n")
    
    # package.json 스캔
    results = scan_directory(target_path)
    
    if not results:
        print("⚠️  package.json 파일을 찾을 수 없습니다.")
        sys.exit(0)
    
    print(f"📦 발견된 프로젝트: {len(results)}개")
    
    # lock 파일도 확인
    lock_file = target_path / "package-lock.json"
    if lock_file.exists():
        lock_result = scan_lockfile(lock_file)
        if lock_result.get("vulnerable"):
            results.append(lock_result)
    
    # 보고서 출력
    vuln_count = print_report(results)
    
    sys.exit(1 if vuln_count > 0 else 0)


if __name__ == "__main__":
    main()