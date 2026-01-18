# React2Shell (CVE-2025-55182) Vulnerability Scanner Collection

React Server Components (RSC) 취약점 탐지 도구 모음입니다. CVE-2025-55182 취약점이 있는 Next.js 및 React 기반 애플리케이션을 탐지합니다.

## CVE-2025-55182 취약점 개요

**React2Shell** 취약점은 React Server Components (RSC)를 사용하는 애플리케이션에서 발견된 원격 코드 실행(RCE) 취약점입니다.

### 취약한 버전

- **React**: 19.0.0 (패치 버전: 19.0.1)
- **Next.js**:
  - 15.0.0 ~ 15.1.3 (패치 버전: 15.1.4)
  - 16.0.0 ~ 16.0.6 (패치 버전: 16.0.7)

### 영향받는 프레임워크

- Next.js (App Router)
- Waku
- TanStack Start
- Shopify Hydrogen
- 기타 RSC를 구현한 프레임워크

## 스캐너 종류

이 저장소는 5가지 스캐너를 제공합니다:

### 1. react2shell_scanner.py
**원격 시스템 취약점 스캐너** (권장)

외부 URL에서 RSC 엔드포인트와 취약한 버전을 탐지합니다.

**특징:**
- RSC Flight 프로토콜 응답 패턴 확인
- Next.js/React 버전 자동 탐지
- 멀티스레드 대량 스캔 지원
- JSON 보고서 생성

**사용법:**
```bash
# 단일 URL 스캔
python react2shell_scanner.py https://example.com

# URL 목록 파일로 대량 스캔
python react2shell_scanner.py urls.txt

# 도메인만 입력 (자동으로 https:// 추가)
python react2shell_scanner.py example.com
```

### 2. react2shell_local_check.py
**로컬 프로젝트 취약점 스캐너**

로컬 프로젝트의 `package.json` 파일을 분석하여 취약한 버전 사용 여부를 확인합니다.

**특징:**
- package.json 기반 버전 확인
- package-lock.json 실제 설치 버전 확인
- 재귀 디렉토리 스캔 (node_modules 제외)
- 패치 권장사항 제공

**사용법:**
```bash
# 현재 디렉토리 스캔
python react2shell_local_check.py

# 특정 디렉토리 스캔
python react2shell_local_check.py /path/to/project
```

### 3. rsc_scan.py (v1.0)
**기본 RSC 탐지 스캐너**

Next.js, Waku, TanStack 등 모든 RSC 구현체를 탐지합니다.

**탐지 방법:**
- RSC 전용 헤더 요청 (Accept: text/x-component)
- Content-Type: text/x-component 확인
- Flight 프로토콜 패턴 매칭
- Vary: rsc 헤더 확인
- Next.js Safe-Check (Server Action 에러 응답)

**사용법:**
```bash
# 단일 URL 스캔
python rsc_scan.py https://example.com

# URL 목록 파일 스캔
python rsc_scan.py urls.txt -o result.json -t 20

# 간략 출력 모드
python rsc_scan.py urls.txt -q
```

### 4. rsc_scan1.py (v1.1)
**개선된 RSC 탐지 스캐너 - Pages Router 구분**

v1.0의 오탐(false positive)을 줄인 버전입니다.

**v1.1 개선사항:**
- Next.js App Router vs Pages Router 구분 로직 추가
- Flight 프로토콜 패턴 정규식 보강
- `_rsc` 쿼리 파라미터 테스트 추가
- Pages Router(구형 SSR)를 RSC로 오진단하는 문제 수정

**사용법:**
```bash
python rsc_scan1.py https://example.com
python rsc_scan1.py urls.txt -o result.json
```

### 5. rsc_scan3.py (v1.2)
**최신 RSC 탐지 스캐너 - 다중 경로 스캔** (가장 권장)

Nuclei 템플릿 기반으로 개선된 최신 버전입니다.

**v1.2 개선사항:**
- 다중 경로 RSC 엔드포인트 스캔: `/`, `/_rsc`, `/app`, `/server`, `/api`, `/actions`
- RSC 에러 메시지 패턴 탐지 추가
- URL 목록 파일 로드 시 특수문자 정리 기능
- HTTPS/HTTP 자동 시도

**사용법:**
```bash
python rsc_scan3.py https://example.com
python rsc_scan3.py urls.txt -o result.json -t 20
```

## 설치

### 필수 요구사항

- Python 3.7 이상
- requests 라이브러리

### 설치 방법

```bash
# 저장소 클론
git clone https://github.com/aquasosal/React2shell-script.git
cd React2shell-script

# 의존성 설치
pip install requests
```

## 사용 예제

### 1. 원격 시스템 스캔

```bash
# 단일 사이트 스캔
python react2shell_scanner.py https://target.com

# 여러 사이트 일괄 스캔
cat > targets.txt << EOF
example.com
test.example.org
https://app.example.net
EOF

python rsc_scan3.py targets.txt -o scan_results.json
```

### 2. 로컬 프로젝트 점검

```bash
# 현재 프로젝트 점검
cd /path/to/my-nextjs-project
python react2shell_local_check.py

# 여러 프로젝트 일괄 점검
python react2shell_local_check.py /path/to/projects/
```

### 3. 결과 해석

**출력 예시:**
```
🔴 [RSC_DETECTED] https://vulnerable-site.com
   └─ RSC Content-Type: text/x-component
   └─ RSC Flight protocol response detected
   └─ VULNERABLE Next.js version: 15.1.2
```

**상태 코드:**
- 🔴 `RSC_DETECTED`: RSC 엔드포인트 탐지됨 (취약 가능성 높음)
- 🟡 `FRAMEWORK_DETECTED`: Next.js/React 프레임워크 감지 (추가 확인 필요)
- 🟢 `NOT_DETECTED`: RSC 미탐지
- ⚠️ `ERROR`: 스캔 중 오류 발생

## 패치 방법

취약점이 발견된 경우 다음과 같이 패치하세요:

### React 패치
```bash
npm install react@19.0.1 react-dom@19.0.1
```

### Next.js 패치
```bash
# Next.js 15.x 사용 시
npm install next@15.1.4

# Next.js 16.x 사용 시
npm install next@16.0.7
```

패치 후 반드시 재배포가 필요합니다.

## 스캐너 선택 가이드

| 목적 | 권장 스캐너 |
|------|------------|
| 외부 사이트 스캔 (가장 정확) | `rsc_scan3.py` (v1.2) |
| 취약 버전 확인 포함 | `react2shell_scanner.py` |
| 로컬 프로젝트 점검 | `react2shell_local_check.py` |
| Pages Router 구분 필요 | `rsc_scan1.py` (v1.1) |
| 빠른 기본 스캔 | `rsc_scan.py` (v1.0) |

## 스캔 옵션

### 공통 옵션

- `-o, --output`: JSON 결과 파일 경로
- `-t, --threads`: 멀티스레드 수 (기본값: 10)
- `--timeout`: 타임아웃 초 (기본값: 10)
- `-q, --quiet`: 간략 출력 모드

### URL 입력 방법

모든 스캐너는 다음 형식을 지원합니다:
- 직접 URL: `python scanner.py https://example.com`
- 도메인만: `python scanner.py example.com` (자동으로 https:// 추가)
- 파일 입력: `python scanner.py urls.txt`

### URL 목록 파일 형식

```text
# 주석은 # 으로 시작
example.com
https://test.example.org
http://legacy.example.net
```

## 윤리적 사용 가이드

이 도구는 **인가된 보안 점검 용도로만** 사용해야 합니다:

- ✅ 자사 시스템 취약점 점검
- ✅ 버그바운티 프로그램 참여
- ✅ 보안 연구 및 교육 목적
- ❌ 무단 침입 및 공격 목적
- ❌ 제3자 시스템 무단 스캔

## 주의사항

1. **대량 스캔 시 주의**: 너무 많은 스레드나 짧은 타임아웃은 대상 시스템에 부하를 줄 수 있습니다.
2. **SSL 경고 무시**: 내부망 자체서명 인증서 대응을 위해 SSL 경고를 무시합니다.
3. **자동 저장**: `-o` 옵션 미지정 시 현재 디렉토리에 결과가 자동 저장됩니다.
4. **오탐 가능성**: 100% 정확도를 보장하지 않으므로 수동 확인이 필요할 수 있습니다.

## 참고 자료

- [CVE-2025-55182 상세 정보](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [React 공식 보안 권고](https://react.dev/blog)
- [Next.js 보안 업데이트](https://nextjs.org/blog)

## 라이선스

이 프로젝트는 교육 및 보안 연구 목적으로 제공됩니다.
윤리적이고 합법적인 용도로만 사용하시기 바랍니다.

## 기여

버그 리포트 및 개선 제안은 이슈로 등록해주세요.

---

**면책조항**: 이 도구의 오용으로 인한 법적 책임은 사용자에게 있습니다.
반드시 인가된 시스템에서만 사용하시기 바랍니다.
