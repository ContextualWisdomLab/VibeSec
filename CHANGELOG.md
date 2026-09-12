# 변경 사항 (CHANGELOG)

## [Unreleased]

### 사용자 경험 (UX)
- 검색창 포커스 전체 키보드 단축키(`/`) 추가 — 단축키가 `<input>`, `<textarea>`, `<select>` 및 `isContentEditable` 요소 외부에서만 작동하도록 제한하여 입력 간섭을 방지하고, 접근성을 위한 힌트 속성(`title`, `aria-keyshortcuts`)을 추가했습니다.
- 대시보드 검색창 커서 유지 — 검색어 중간에서 텍스트를 수정할 때마다 커서가 검색어의 맨 끝으로 점프하는 불편함을 수정했습니다. 이제 입력창의 커서 위치(`selectionStart`/`selectionEnd`)가 동적 렌더링 이후에도 원래 위치에 정확히 유지되어 자연스러운 타이핑 경험을 제공합니다.

### 보안
- Claude plugin GitHub merge/release detector 계보를 최신 #1169 위로 ordinary two-parent merge했습니다. #1170 exact head `f5c75be…`는 current parent보다 5 ahead / 0 behind이며 checksum nested-path·exact `..` 경계와 GitHub command-context delta를 함께 보존합니다. Targeted GitHub/checksum 60/60과 전체 Claude-plugin 383/383, compile·diff check가 통과했습니다. Hosted exact-head workflow와 독립 review가 없어 Draft입니다.
- Claude plugin successor 계보를 #1169까지 확장했습니다. #1163 command/agent rule reuse, #1164 hide-actions/self-modify/goal-escalation, #1165 setuid/setgid/world-writable mode, #1166 archive decompression/aggregate admission, #1167 scanner release/policy provenance, #1168 deterministic CycloneDX SBOM receipt digest, #1169 first-party checksum admission을 ordinary two-parent merge로 승계해 모두 current parent보다 0 behind로 만들었습니다. #1169는 nested checksum path basename-collapse FN과 정상 `..safe.bin` traversal FP를 RED→GREEN으로 수선했습니다. Exact-tree Claude-plugin 회귀는 265/265에서 352/352까지 누적 통과했으며, hosted exact-head workflow와 독립 review가 없어 모두 Draft입니다.
- Claude plugin successor 계보를 #1161까지 복구했습니다. #1150 browser profile부터 #1156 vendored scope, 기존 #1157 invocation identity, #1158 secret-to-prompt, #1161 secret-to-MCP를 최신 parent 위로 ordinary two-parent merge했고 모든 head가 current parent보다 0 behind입니다. Exact-tree Claude-plugin 회귀는 #1150 153/153에서 #1161 256/256까지 증가하며 통과했습니다. Hosted exact-head workflow와 독립 review가 없어 모두 Draft입니다.
- 대시보드 모바일 overflow 수선 — hosted Chromium RED `1d5adbc…`가 390px viewport에서 document 563px를 측정했습니다. Exact `4dbee0e…`에서 table fixed layout과 cell wrapping으로 root cause를 수선했고 Python 3.11/3.13 1003/1003 및 artifact `10066505328`(198275 bytes, SHA-256 `5b3dd4…`)로 검증했습니다.
- 대시보드 responsive hostile-payload 증거 — #1192 exact `c98c301…`에서 Chromium 기반 1003/1003을 Python 3.11/3.13 모두 통과하고, 1280×800·390×844 list/detail 장면과 exact revision manifest를 artifact `10066280431`(203095 bytes, SHA-256 `ea8f45…`)으로 결속했습니다. 이는 browser artifact Gap만 닫으며 CodeQL handoff·독립 승인을 대체하지 않습니다.
- 대시보드 exact-head 회귀 복구 — #1192의 concurrent `1456e14…`가 `parseInt` 부분 숫자 허용과 Chromium/browser/static corpus 삭제를 재도입한 결함을 확인했습니다. Normal atomic descendant `7e1bb470…`에서 whole-value `Number`·non-negative safe-integer 계약과 #1117 browser prerequisite를 완전히 복구했습니다. `215fa089…`의 hosted Python 3.11/3.13 1003/1003은 predecessor 증거이며 새 exact head로 이전하지 않습니다.
- Exact-head review-control 증거를 갱신했습니다. #1192는 #1117 browser prerequisite를 non-force two-parent merge로 승계했고, 후속 concurrent commit이 삭제한 Chromium workflow·잠금 의존성·browser/static regressions를 복구했습니다. Count는 전체 `Number` 값 중 non-negative safe integer만 허용해 `12px`, 소수, 음수, Infinity와 markup을 0으로 투영하며, hostile list/detail payload, `data-id` round-trip, inherited severity fallback, injected DOM/dialog 부재를 browser oracle로 검증합니다. Predecessor Checks는 이전하지 않습니다. #999 predecessor는 9개 repository workflow가 GREEN이나 Required Noema가 `orchestrator/free` 다중 429/timeout 뒤 HTTP 502로 실패했습니다. Canonical owner contextual-orchestrator #1094의 protected merge·immutable release·consumer bump 전에는 review 실패를 `Clean Scan`이나 승인으로 바꾸지 않습니다.
- Control-plane 대시보드 보안 회귀를 복원했습니다. Concurrent commit이 삭제한 JSON 렌더링 계약을 기존 dashboard security test owner에 통합하고, 숫자 coercion·`data-id` escape·severity own-property 경계와 정확한 innerHTML RCA를 #1192 exact head에 연결했습니다.
- Claude plugin GitHub 실행 경계 보강 — canonical #1170이 structural manifest의 typed `command`/`args`와 bounded nested-shell payload를 공통 parser로 소비합니다. `gh pr merge`와 `gh release create|upload|delete|edit`는 fail-closed하며 description/reporting/assignment/noexec, malformed argv, near verb, non-write verb는 negative로 유지합니다. 수선은 #1171→#1172→#1173에 non-force로 승계됐습니다.
- Claude plugin kubectl/Docker 실행 경계 보강 — canonical #1172가 structural manifest의 typed `command`/`args`와 bounded nested-shell payload를 공통 parser로 소비합니다. `kubectl apply`, `docker push`, `docker image push`는 fail-closed하며 description prose, reporting/no-op command, assignment, noexec, near verb, malformed argv는 negative로 유지합니다. #1173은 해당 prerequisite를 non-force로 통합했습니다.
- Claude plugin 구조화 argv 검출 보강 — JSON manifest의 `command`와 sibling `args`를 하나의 직접 실행 경계로 검증하여 `terraform apply`·`helm install` 우회를 차단합니다. Wrapper/reporting executable, near-verb, 공백 포함 단일 인자, 비배열·혼합형 `args`는 실행으로 추정하지 않으며 기존 shell-string 명령은 그대로 보존합니다.
- Claude plugin nested shell 검출 보강 — 직접 `sh`/`bash`/`dash`/`ksh`/`zsh`의 `-c` option payload와 구조화 shell argv를 bounded하게 재검사합니다. Split·compact·repeated `c`, 공통 no-value option과 Bash 전용 실행 보존 short/long option을 명시적으로 지원합니다. Noexec `n`, Bash `-D`·dump-string, dash/sh의 `-r`, 값 소비 option, missing-`c`, Bash short-before-long 순서는 실행으로 오인하지 않습니다. Reporting·assignment·wrapper·comment prose와 `$0…` 후속 인자는 payload로 합치지 않고 `apply-now`·`install-chart` near-verb도 제외합니다.
- Claude plugin 실행 명령 경계 보강 — quoted CLI 이름(`"deno" publish`, `'pod' trunk push`)을 실제 registry write로 검출하고, quoted near-task suffix는 capability 오탐에서 제외합니다. 공통 parser는 `:`·`true`·`false`의 인자를 실행 명령으로 오인하지 않으며, 뒤따르는 실제 명령은 계속 검출합니다.
- Claude plugin sbt publish 검출 보강 — `sbt "publish"`·`sbt 'publishSigned'`과 `$(...)`/backtick 안의 인용 task도 실제 repository write로 검출합니다. `publishLocal`, assignment·reporting prose, 닫힌 here-document payload는 계속 negative입니다.
- Claude plugin 실행 명령 문맥 정밀화 — 닫힌 literal here-document 본문의 `terraform apply`/`helm install` 같은 문자열은 데이터로 취급해 HIGH 오탐을 제거했습니다. 인용 delimiter와 `<<-` 탭 제거 형식을 지원하며, 닫히지 않거나 모호한 형식은 fail-closed로 유지합니다. 종료 delimiter 뒤의 실제 명령과 인용/주석 opener 유사 문자열 뒤의 실제 명령은 계속 검출합니다.
- 리포트 출력 하드닝 — 생성된 markdown 리포트가 HTML로 렌더될 때 악성 finding 내용(예: 외부 엔진이 스캔한 코드의 `<script>`)이 주입되지 않도록, 프로즈 필드(message/remediation/verification)를 HTML 이스케이프하고 snippet의 code-fence 탈출을 무력화합니다(모든 리포트 타입). rule_id/category/context 등 제약된 식별자는 그대로 둡니다.
- control plane API 하드닝: (1) 요청 본문을 10MiB로 캡하고 음수 Content-Length를 거부합니다(유효 키 소지자의 OOM/EOF-hang 방지). (2) `limit`/`offset` 쿼리 파라미터를 클램프합니다 — sqlite에서 `LIMIT -1`은 무제한이므로 음수를 그대로 전달하면 페이지네이션 캡이 우회됐습니다(list 1..1000, trend 1..365, offset ≥0).

### 추가
- AWS CloudFormation 템플릿 misconfiguration 룰팩 `scanner/rules/cloudformation.yml`을 추가했습니다(정밀 룰 6종, YAML/JSON/`.template` 대상). Terraform-AWS는 기존 엔진이 커버하지만 raw CFN 템플릿은 공백이었습니다. 모든 패턴을 CFN 고유 컨텍스트(`AWS::` 리소스 타입, PascalCase 속성명)에 앵커링해 Kubernetes 매니페스트·docker-compose·GitHub Actions 워크플로 같은 YAML 유사 파일에서는 발화하지 않음을 테스트로 검증했습니다.
  - `cfn-iam-policy-star-star` — IAM 정책이 `Action`·`Resource` 모두 와일드카드(사실상 계정 전체 관리자 권한). Statement 경계를 넘는 오탐 차단. CRITICAL.
  - `cfn-s3-bucket-public-acl` — S3 버킷 `AccessControl`이 PublicRead/PublicReadWrite(전 세계 공개). HIGH.
  - `cfn-security-group-open-world` — 보안 그룹 ingress가 `0.0.0.0/0`·`::/0`에 개방(기본값인 open egress는 오탐 없이 통과). HIGH.
  - `cfn-rds-publicly-accessible` — `PubliclyAccessible: true`(DB 인스턴스 인터넷 직접 노출). HIGH.
  - `cfn-storage-unencrypted` — RDS `StorageEncrypted: false` 또는 EBS 볼륨 `Encrypted: false`(저장 데이터 미암호화). HIGH.
  - `cfn-secret-parameter-default` — 시크릿 성격 이름의 Parameter에 리터럴 `Default` 값 커밋(`{{resolve:...}}` 동적 참조는 안전으로 통과). HIGH.
- `tests/test_cloudformation_rules.py` — 룰별 양성/음성 패턴 테스트, severity 검증, e2e 스캔(오염 템플릿에서 6종 전부 발화, 안전 템플릿 0건), k8s/compose/GitHub Actions look-alike 음성 테스트 포함(총 29건).

### 추가
- `appguardrail fix` 명령 — 안전하고 결정적인 자동 수정을 적용합니다(기본 dry-run diff, `--apply`로 기록). 의미를 바꾸지 않는 순수 additive 변환만 수행하며, 첫 변환으로 외부 `target="_blank"` 링크에 `rel="noopener noreferrer"`를 추가합니다(reverse tabnabbing 방지). 동작을 바꾸는 수정(시크릿→env 등)은 위험하므로 자동 적용하지 않고 fix-pack 프롬프트로 남깁니다. scan→fix→verify 루프를 안전하게 닫습니다.
- `appguardrail serve` — 멀티테넌트 **control-plane API**(스캔 인제스트 + 히스토리). 일회성 CLI를 넘어, CI가 매 스캔의 `appguardrail.findings.v1`을 org별 API 키로 영속 저장하고 시간에 따른 추이를 조회할 수 있는 지속형 백본입니다. stdlib(sqlite3 + http.server)만 사용하며 org별 테넌트 격리를 강제합니다.
  - 엔드포인트: `POST /api/v1/scans`(인제스트), `GET /api/v1/scans`(히스토리), `GET /api/v1/scans/{id}`(상세), `GET /api/v1/health`.
  - 인증: `Authorization: Bearer <api_key>`. `--create-org <name>`으로 org·키 발급, 빈 DB면 기본 org를 부트스트랩합니다.
  - **org console** — control-plane 서버가 `/`에서 서빙하는 단일 정적 페이지(`scanner/dashboard/console.html`). API 키로 연결해 스캔 히스토리, deploy-blocking 추이, 스캔 상세를 봅니다(프레임워크·빌드 단계 없음).
  - **drift 감지** — 인제스트 시 같은 org+repo의 직전 스캔 대비 **신규 deploy-blocking** 수(`new_blocking`)를 계산합니다(line-독립 지문). console과 API 응답에 노출됩니다.
  - **API 페이지네이션 + trend** — `GET /api/v1/scans?limit=&offset=`로 스캔 히스토리를 페이징하고, `GET /api/v1/scans/trend?limit=`로 시간순(오래된→최신) deploy_blocking·new_blocking 시계열을 얻습니다(차트용).
  - **RBAC / 멀티유저** — org별 다중 API 키에 역할(viewer/member/owner)을 부여합니다. viewer=읽기, member=스캔 인제스트, owner=webhook·키 발급 포함 전체. `POST /api/v1/keys`(owner)로 역할 지정 키를 발급합니다. 부트스트랩 키는 owner입니다.
  - **drift 알림 webhook** — org에 webhook URL을 설정하면(`POST /api/v1/webhook`) `new_blocking > 0`인 스캔에서 알림을 POST합니다(best-effort, 인제스트 실패 안 함). detect→alert 루프를 닫습니다.
  - **Slack 포맷 drift 알림** — webhook 호스트가 `hooks.slack.com`이면 payload를 Slack Block Kit 메시지(헤더 + org·신규 blocker 수·repo·scan, 상위 5개 `rule_id`/파일 목록과 `+N more` 오버플로)로 자동 렌더링해 Slack Incoming Webhook이 읽기 좋은 카드로 표시합니다. 그 외 URL은 기존 generic JSON payload를 그대로 받습니다(하위 호환). 무의존성 유지를 위해 stdlib만 사용하며 텍스트는 이스케이프·트림합니다.
  - `appguardrail scan --push <url>` — 스캔 후 findings를 control-plane에 POST합니다(키는 `APPGUARDRAIL_API_KEY`, repo/commit은 `GITHUB_REPOSITORY`/`GITHUB_SHA`에서 자동). CI가 매 스캔을 플랫폼에 밀어넣어 continuous-monitoring 루프를 닫습니다.
  - `appguardrail monitor` 워크플로가 `APPGUARDRAIL_CONTROL_PLANE_URL` secret이 설정된 경우 스캔을 control-plane에 자동 push합니다(`APPGUARDRAIL_API_KEY` secret 사용). 미설정 시 기존 SARIF+게이트 동작 그대로.
- `appguardrail sbom` — 의존성 매니페스트(npm `package-lock.json`/`package.json`, Python `requirements.txt`)에서 CycloneDX 1.5 SBOM을 생성합니다. 무의존성(stdlib)으로 동작하며, lockfile이 있으면 resolved 버전을, 없으면 매니페스트의 declared 범위를 사용하고 컴포넌트 properties에 출처를 기록합니다. 공급망 실사(due diligence)의 기본 산출물입니다.
- `appguardrail sbom`의 lockfile 파서를 확장했습니다 — `poetry.lock`(pypi), `pnpm-lock.yaml`·`yarn.lock`(npm)을 추가로 인식합니다. 서드파티 toml/yaml 라이브러리 없이 stdlib만으로 손수 파싱하며(정규식·라인 스캔), scoped npm 패키지(`@scope/name`)·pnpm peer-dependency 접미사·yarn 다중 spec 헤더를 처리하고 resolved 버전으로 기록합니다. npm 측은 `package-lock.json` > `pnpm-lock.yaml` > `yarn.lock` > `package.json` 순으로 우선하고, `poetry.lock`은 Python 측에 additive로 더해집니다.

### 추가
- 프로젝트 설정 파일 `.appguardrail.json`(선택) — deploy 게이트를 CLI 플래그 없이 팀 단위로 조정합니다. 무의존성 유지를 위해 JSON을 사용합니다.
  - `fail_on`: 게이트를 실패시키는 최소 severity(예: `"HIGH"`, `"CRITICAL"`). 기본은 CRITICAL·HIGH.
  - `exclude_rules`: 게이트에서 제외할 rule id 목록(억제). 잘못된 값은 스캔을 조용히 통과시키지 않고 오류로 실패합니다.
- 탐지 룰 추가(AI-built 앱 스택 정밀 룰, 저 오탐):
  - `sql-injection-raw-unsafe` — Prisma `$queryRawUnsafe`/`$executeRawUnsafe`(파라미터화 없이 SQL 주입 가능). CRITICAL.
  - `react-dangerously-set-inner-html` — React `dangerouslySetInnerHTML`(사용자 입력 시 XSS). HIGH.
  - `hardcoded-anthropic-api-key` — `sk-ant-…` Claude API 키 하드코딩. CRITICAL.
- 시크릿·주입 탐지 룰 8종 추가(고정밀, 안전 코드 오탐 0 검증):
  - `hardcoded-aws-access-key-id`(AKIA/ASIA), `hardcoded-github-token`(ghp_/github_pat_), `hardcoded-google-api-key`(AIza), `hardcoded-private-key-block`(PEM) — 모두 CRITICAL.
  - `supabase-auth-admin-client-usage`(auth.admin.* 클라이언트 노출), `node-open-redirect-user-input`(req 입력 redirect), `insecure-random-security-token`(토큰에 Math.random) — HIGH.
  - `wildcard-postmessage-target`(postMessage 대상 '*') — WARNING.
- 제공자별 고정밀 시크릿 탐지 룰 6종 추가(distinctive prefix 기반, 안전 코드 오탐 0 검증):
  - `hardcoded-slack-token`(xoxb/xoxa/xoxp/… Slack 토큰), `hardcoded-twilio-credential`(Twilio Account SID `AC…`/API key `SK…`), `hardcoded-sendgrid-api-key`(`SG.` SendGrid 키), `hardcoded-npm-token`(`npm_` npm 토큰), `hardcoded-pypi-token`(`pypi-AgEIcHlwaS…` PyPI 토큰) — 모두 CRITICAL.
  - `hardcoded-slack-webhook-url`(`hooks.slack.com/services/…` incoming webhook) — HIGH.
  - 모든 룰에 `cwe: [CWE-798]`, `owasp: [A07:2021]` 부여. 기존 룰(OpenAI/Anthropic/Stripe/AWS/GitHub/Google/PEM)과 중복 없음.

### 추가
- `appguardrail scan --sarif <path>` — 정규화된 findings를 SARIF 2.1.0으로 출력합니다. GitHub code scanning(`github/codeql-action/upload-sarif`), VS Code SARIF viewer, Azure DevOps 등 SARIF 소비 도구가 그대로 읽어 Security tab 알림·PR 인라인 주석으로 표시됩니다. severity→level 매핑과 GitHub 랭킹용 `security-severity` 속성, deploy-gate 의미(`deployBlocking`), 재실행 간 안정적인 `partialFingerprints`를 포함합니다.
- `appguardrail monitor`가 설치하는 워크플로가 이제 SARIF를 생성해 GitHub code scanning에 업로드합니다(`security-events: write`). deploy 게이트는 그대로 유지됩니다.
- `appguardrail dashboard` 명령을 추가했습니다. `scan --findings-json`이 생성한 `appguardrail.findings.v1` 파일을 로컬 웹 대시보드로 렌더링합니다. severity 요약, deploy-blocking 게이트, 카테고리별 findings, 그리고 finding별 상세(AppGuardrail Fix Format: Problem / Fix Prompt / Verification)를 보여줍니다.
  - 옵션: `--findings`, `--port`, `--host`, `--no-open`.
  - 대시보드는 프레임워크·빌드 단계가 없는 단일 정적 페이지(`scanner/dashboard/index.html`)이며, wheel에 포함되어 `pip install` 설치본에서도 동작합니다.
  - findings 파일을 `/findings.json`으로 직접 서빙하여 실행 위치(cwd)와 무관하게 로드됩니다.

### 검증
- `tests/test_dashboard_core.py`: 정적 자산 동봉 여부, HTTP 라우트(`/`, `/findings.json`, 404) 테스트를 추가했습니다.
- 격리된 venv에 wheel을 설치해 소스 트리 밖에서 `appguardrail dashboard`가 대시보드를 서빙함을 확인했습니다.

## [0.1.1] - 2026-06-25

### 변경
- PyPI Trusted Publishing 경로 검증을 위한 패치 릴리스로 CLI 버전을 `0.1.1`로 갱신했습니다.

### 검증
- GitHub `pypi` environment와 PyPI Trusted Publisher 설정을 사용해 GitHub Actions OIDC 게시 경로를 검증합니다.

## [0.1.0] - 2026-06-25

### 변경
- 프로젝트명을 AppGuardrail로 변경했습니다. 기존 VibeSec 이름은 제3자 PyPI `vibesec` 네임스페이스와 충돌할 수 있어, 설치 경로와 공개 식별자의 신뢰성을 높이기 위한 조치입니다.
- 문서화된 CLI 명령, 생성 rule 파일명, scan artifact 이름, 저장소 참조를 `appguardrail` 기준으로 갱신했습니다.

### 추가
- PyPI 배포를 위한 `pyproject.toml`, package discovery 설정, `appguardrail` console script entry point를 추가했습니다.
- GitHub Actions 기반 PyPI Trusted Publishing workflow를 추가했습니다.
- `scanner/cli/appguardrail.py`의 100% 테스트 커버리지를 달성하기 위해 `tests/test_appguardrail_coverage.py` 테스트 파일을 추가했습니다.
  - `cmd_init`: `claude-code` 사용 시 `append_marker` 관련 파일 생성 및 심볼릭 링크 예외, 경로 이탈(`path traversal`) 방지 테스트 추가.
  - `cmd_scan`: 존재하지 않는 경로 및 심볼릭 링크 경로 스캔 시 예외 처리 테스트 추가.
  - `cmd_hook`: `.git` 디렉토리 부재 시 에러 반환, 훅 스크립트의 정상 설치, 심볼릭 링크 처리 및 경로 이탈 방지 테스트 추가.
  - 파일 시스템 IO: 파일 디렉토리 순회(`_collect_files`) 시 `os.scandir` 및 하위 노드의 `OSError` 처리 테스트 추가. 파일 정보 획득(`os.lstat`) 과정의 권한 및 예외(`OSError`) 처리 테스트 추가.
  - `cmd_review`: `--stack`, `--db`, `--payments` 인자 유무에 따른 프롬프트 생성 분기 테스트 추가.
  - `main` 함수: 터미널 인자(args) 파싱 및 서브 커맨드(`init`, `scan`, `review`, `hook`) 호출, 그리고 인자가 없을 때의 예외 동작을 포함한 테스트 추가.
  - `if __name__ == '__main__':` 블록의 실행 테스트 추가.
- `scanner/cli/appguardrail.py`의 엣지 케이스를 커버하기 위한 `tests/test_coverage_edge_cases.py` 테스트 파일을 추가했습니다.
  - `_run_trivy_fs`: Trivy 스캔 시의 비정상 종료 및 JSON 파싱 에러 처리 테스트 추가.
  - `_finding_context`, `_finding_category`, `_trivy_severity`, `_confidence`, `_is_deploy_blocking` 등 헬퍼 함수들의 다양한 입력값에 대한 반환값 테스트 추가.
  - `_trivy_target`: 절대 경로, 상대 경로 및 빈 문자열 입력 처리 엣지 케이스 추가.

### Performance (성능 개선)
- `scanner/cli/appguardrail.py`에서 `Path.open()` 대신 내장 `open()` 함수를 사용하여 파일 스캔 시 오버헤드 감소
- `_trivy_severity` 및 `_print_scan_results` 함수 내 딕셔너리 객체를 모듈 레벨 상수로 추출하여 메모리 할당 최적화

### 검증
- `scanner/cli/appguardrail.py` 전체 코드에 대한 테스트 커버리지 100% 달성 및 기존 기능의 안정성 확보 검증.
