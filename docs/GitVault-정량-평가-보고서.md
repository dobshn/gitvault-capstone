# GitVault 정량 평가 보고서

## 1. 요약

GitVault의 기본 연산, 파일 크기에 따른 지연시간, 주요 내부 단계, Nostr relay 가용성, rollback/fork 탐지 비용을 실제로 측정했다. 모든 수치는 `Release` 빌드(`-O3 -DNDEBUG`)에서 5회 반복한 결과다.

핵심 결과는 다음과 같다.

- 실제 Dropbox와 공용 Nostr relay 3개를 사용한 60개 명령이 모두 성공했다.
- 종단간 지연시간 중앙값은 `status` 3.998초, `mkdir` 17.849초였다.
- `add`는 8 KiB에서 17.458초, 10 MiB에서 19.985초로 증가했다. 작은 파일에서는 CAS·checkpoint·relay 동기화의 고정 비용이 지배적이었다.
- `cat`은 8 KiB에서 6.445초, 10 MiB에서 9.473초로 증가했다. 같은 구간에서 blob 다운로드 중앙값은 0.668초에서 3.713초로 증가했다.
- rollback 판단은 중앙값 0.255 ms, incompatible vector clock에 의한 fork 판단은 0.539 ms였다. 두 시나리오 모두 5/5회 정확히 탐지했다.
- 35회 write 후 한 replica의 로컬 trust 상태는 4,110 bytes와 최신 witness 파일 1개였다. 이는 한 시점의 관측값이며, 연산 수에 대한 공간 복잡도를 단독으로 입증하는 결과는 아니다.

## 2. 평가 설계

SiRiUS의 파일 크기별 기본 파일 연산 평가 방식과 SUNDR의 종단간 연산 비용 및 보안 프로토콜 비용 분리 방식을 참고했다. GitVault에 맞게 다음 세 범주로 단순화했다.

1. 사용자 관점의 종단간 지연시간: `init`, `status`, `mkdir`, `add`, `cat`, `remove`
2. 대표 read/write의 단계별 지연시간: 인증·KDF, freshness 확인, object 처리, Dropbox CAS, signed checkpoint 확정
3. 보안 판단 비용과 성공 여부: rollback, fork, CAS conflict 및 relay 장애 복구

### 2.1 환경

| 항목 | 설정 |
|---|---|
| 측정 시각 | 2026-08-12 16:43–16:58 KST |
| Git 기준 커밋 | `956951999665bf1b6c3138d59a4661e150e32eb8` + 본 평가 instrumentation |
| 빌드 | CMake `Release`, Apple Clang 21.0.0, `-O3 -DNDEBUG` |
| 장비 | MacBook Pro, Apple M1 Pro 10-core, RAM 32 GB |
| OS | macOS 26.5.2, arm64 |
| Cloud | 실제 Dropbox 계정 및 revision 기반 conditional upload(CAS) |
| Nostr | `relay.damus.io`, `relay.primal.net`, `relay.ditto.pub` |
| Quorum | write `W=2`, read `R=2`, 총 relay 3개 |
| 반복 횟수 | 각 조건 5회 |
| 파일 데이터 | `os.urandom`으로 생성한 8 KiB, 1 MiB, 10 MiB |

각 명령은 별도 프로세스로 실행했으므로 종단간 시간에는 프로세스 시작, Dropbox 인증 준비, KDF/identity 로드, Dropbox 통신, relay 통신이 포함된다. `init`은 서로 다른 임시 vault 5개에서 측정했고, 나머지 연산은 첫 번째 vault에서 순차 실행했다. `add` 직후 같은 파일을 `cat`하고 `remove`했으므로 remove 행의 크기는 삭제 대상이었던 파일 크기이며, remove 자체가 blob 본문을 재전송한다는 의미는 아니다.

보고서의 p95는 표본 5개의 선형 보간값이다. 표본 수가 작기 때문에 장기적인 tail latency 추정치가 아니라 이번 실행 내 최댓값에 가까운 기술 통계로 해석해야 한다.

## 3. 종단간 연산 지연시간

단위는 초이며, 각 행의 성공 횟수는 5회 중 성공한 횟수다.

| 연산 | 데이터 크기 | 중앙값 | p95 | 최소–최대 | 성공 |
|---|---:|---:|---:|---:|---:|
| `init` | - | 10.558 | 11.311 | 9.921–11.449 | 5/5 |
| `status` | - | 3.998 | 5.066 | 3.666–5.323 | 5/5 |
| `mkdir` | - | 17.849 | 19.235 | 17.223–19.397 | 5/5 |
| `add` | 8 KiB | 17.458 | 18.312 | 16.857–18.472 | 5/5 |
| `add` | 1 MiB | 17.496 | 18.484 | 16.381–18.598 | 5/5 |
| `add` | 10 MiB | 19.985 | 21.592 | 19.219–21.871 | 5/5 |
| `cat` | 8 KiB | 6.445 | 8.578 | 6.331–8.871 | 5/5 |
| `cat` | 1 MiB | 7.495 | 9.688 | 6.769–9.980 | 5/5 |
| `cat` | 10 MiB | 9.473 | 10.544 | 9.094–10.775 | 5/5 |
| `remove` | 8 KiB 대상 | 18.178 | 18.445 | 17.681–18.476 | 5/5 |
| `remove` | 1 MiB 대상 | 18.975 | 20.386 | 17.089–20.522 | 5/5 |
| `remove` | 10 MiB 대상 | 18.293 | 18.856 | 16.948–18.946 | 5/5 |

8 KiB 대비 10 MiB에서 `add` 중앙값은 14.5%, `cat`은 47.0% 증가했다. 반면 `remove`는 18.178초에서 18.293초로 0.6%만 변했다. 이는 remove가 파일 blob을 다시 내려받거나 올리지 않고, tree/commit 갱신과 CAS/checkpoint 프로토콜을 수행하기 때문이다. 다만 각 조건이 5회뿐이므로 이 비율에 대한 신뢰구간은 산출하지 않았다.

## 4. 주요 단계별 지연시간

아래 단계들은 서로 중복되지 않는 상위 구간을 선택했다. 각 열은 해당 단계의 5회 중앙값이며 단위는 ms다. 단계별 중앙값을 독립적으로 계산했으며, CLI 설정·인증 준비처럼 instrumentation 밖에 있는 시간도 있으므로 단계의 합은 종단간 중앙값과 정확히 일치하지 않는다.

### 4.1 Add

| 단계 | 8 KiB | 1 MiB | 10 MiB |
|---|---:|---:|---:|
| KDF 및 vault identity 로드 | 184.756 | 191.213 | 188.267 |
| write 전 cloud/relay freshness 확인 | 2,444.156 | 2,390.274 | 2,275.806 |
| 암호화 object 준비 및 업로드 | 3,647.677 | 3,272.962 | 6,239.755 |
| 복구용 HEAD journal 저장 | 1.625 | 1.367 | 1.763 |
| 재검증, Dropbox CAS/readback, checkpoint `W=2`, 최종 확인 | 7,934.107 | 8,605.329 | 8,587.393 |
| **종단간** | **17,458.244** | **17,496.047** | **19,985.272** |

10 MiB의 object 준비·업로드는 8 KiB보다 2.592초 길지만, freshness/CAS/checkpoint 경로는 데이터 크기와 무관하게 약 10–11초의 고정적인 상위 단계 비용을 만든다. 따라서 현재 환경에서는 작은 파일의 암호화 자체보다 원격 일관성 프로토콜이 더 큰 비용이다.

### 4.2 Cat

| 단계 | 8 KiB | 1 MiB | 10 MiB |
|---|---:|---:|---:|
| KDF 및 vault identity 로드 | 192.000 | 189.875 | 186.072 |
| cloud/relay freshness 확인 | 2,371.223 | 2,802.464 | 2,193.370 |
| commit/tree 경로 해석 | 1,793.378 | 1,747.436 | 1,756.215 |
| 파일 blob 다운로드 | 667.641 | 1,142.458 | 3,712.657 |
| blob 복호화 및 무결성 검증 | 0.147 | 10.605 | 78.133 |
| **종단간** | **6,445.467** | **7,495.438** | **9,472.784** |

파일 크기가 커질 때 가장 크게 늘어난 단계는 blob 다운로드였다. 8 KiB에서 10 MiB로 갈 때 다운로드 중앙값은 5.56배가 됐다. 10 MiB 복호화·검증은 78.133 ms로 전체 `cat` 중앙값의 약 0.82%였다.

### 4.3 Init과 relay 상태 확인

`init`의 주요 단계 중앙값은 KDF/identity 생성 1,241.758 ms, 초기 object/HEAD 생성 2,963.302 ms, cloud HEAD 확인 583.664 ms, Genesis `W=2` 게시 1,697.044 ms, 최초 checkpoint `W=2` 게시 1,653.917 ms였다. 전체 중앙값은 10,557.824 ms였다.

`status`에서 관측한 relay별 EOSE 지연은 다음과 같다.

| Relay | EOSE 성공 | 성공 응답 중앙값 | p95 | 관측 사항 |
|---|---:|---:|---:|---|
| damus | 4/5 | 1,213.5 ms | 2,866.9 ms | 1회 WebSocket handshake 거절(431 ms) |
| primal | 5/5 | 1,716.0 ms | 1,813.0 ms | - |
| ditto | 5/5 | 1,413.0 ms | 1,506.6 ms | - |

damus가 한 번 실패했지만 나머지 두 relay가 `R=2`를 만족해 모든 `status`가 `CONSISTENT`로 성공했다. 이는 단일 relay 장애를 허용하는 quorum 구성이 실제 실행에서도 동작한 사례다. damus의 통계는 성공한 4개 응답만 사용했다.

## 5. Rollback/Fork 탐지 평가

네트워크 변동과 탐지 알고리즘 자체 비용을 분리하기 위해 메모리 내 통제 실험을 수행했다. 각 프로세스에서 rollback과 fork 시나리오를 한 번씩 비계측 warm-up한 후, 5회를 측정했다. 측정 구간에는 signed event의 event ID·Schnorr signature 검증, NIP-44 복호화, vector clock 비교와 상태 결정이 포함되고 disk/network I/O는 포함되지 않는다.

| 시나리오 | 구성 | 중앙값 | p95 | 최소–최대 | 정확한 탐지 |
|---|---|---:|---:|---:|---:|
| Rollback | local trusted/signed checkpoint보다 cloud clock이 뒤에 있음 | 0.255 ms | 0.348 ms | 0.143–0.359 ms | 5/5 |
| Fork | 서로 incompatible한 signed checkpoint 2개 | 0.539 ms | 0.606 ms | 0.504–0.620 ms | 5/5 |

fork 시나리오는 서명된 event 두 개를 검증·복호화하므로 signed witness 한 개를 처리하는 rollback 시나리오보다 중앙값이 약 2.11배였다. 절대 판단 비용은 모두 1 ms 미만이었고, 실제 명령 지연은 이 연산보다 Dropbox/relay 왕복시간에 의해 지배됐다.

추가로 coordinator 통합 시나리오 전체를 매회 새로운 임시 fixture에서 5회 실행했다. 이 시나리오는 두 client의 comparable clock 갱신, stale revision CAS conflict, 비활성 replica component 유지, relay `W=1` 이후 journal/outbox 복구, `R<2` degraded read, incompatible signed checkpoint fork 탐지를 함께 검증한다. 5/5회 성공했고 실행시간 중앙값은 960.754 ms, p95는 972.940 ms였다. 이 시간은 여러 시나리오를 묶은 테스트 suite 실행시간이며 단일 사용자 연산 지연으로 해석해서는 안 된다.

## 6. 저장공간 관측

첫 번째 vault에서 `mkdir` 5회와 `add`/`remove` 30회, 총 35회 write를 완료한 직후 로컬 `trust` 디렉터리는 4,110 bytes였고, replica별 최신 signed checkpoint인 witness 파일은 1개였다. 이후 benchmark가 만든 Dropbox vault 5개와 로컬 메타데이터는 모두 삭제했다.

이 결과는 현재 구현이 같은 replica의 witness를 주소 기반 파일 하나에 덮어쓰는 동작과 일치한다. 그러나 다음 두 이유로 이번 단일 snapshot만으로 “연산 수와 무관한 완전한 상수 bytes”를 실험적으로 입증했다고 표현해서는 안 된다.

- vector clock의 엔트리 수는 연산 수가 아니라 참여 replica 수에 따라 증가한다.
- counter의 직렬화 길이와 checkpoint JSON 길이는 값의 자릿수에 따라 소폭 달라질 수 있다.

따라서 논문에는 “최신 checkpoint 개수는 replica당 하나이며 전체 history에 비례하지 않는다”라고 기술하고, 엄밀한 공간 평가는 연산 수와 replica 수를 독립변수로 둔 후속 실험으로 보완하는 것이 적절하다.

## 7. 해석과 한계

이번 결과가 직접 뒷받침하는 결론은 다음과 같다.

- 현재 구현에서 file size에 민감한 부분은 `add`의 object 준비·업로드와 `cat`의 blob 다운로드·복호화다.
- 작은 파일의 write latency는 Dropbox CAS와 Nostr quorum을 포함한 고정 프로토콜 비용이 지배한다.
- vector clock 기반 rollback/fork의 로컬 판정 비용은 1 ms보다 작다.
- 한 relay의 transport failure가 있어도 `R=2 of 3`으로 정상 상태 판정이 가능했다.

다음 항목은 이번 결과만으로 일반화할 수 없다.

- 표본이 조건별 5개이고 한 장비·한 Dropbox 계정·한 시간대에서 측정했다.
- 공용 relay와 인터넷 상태의 변동이 결과에 포함되어 있다.
- geographically distributed client의 동시 write 성능은 측정하지 않았다. CAS conflict는 통제 fixture에서 correctness만 검증했다.
- Dropbox 단독 파일시스템이나 SiRiUS/SUNDR 구현과의 직접 비교군이 없으므로 절대적인 경쟁 시스템 대비 overhead는 계산할 수 없다.
- 파일 개수, directory 폭/깊이, replica 수를 바꾼 확장성 실험은 포함하지 않았다.
- 임시 Dropbox/로컬 vault는 삭제했지만 공용 relay에 게시된 NIP-44 암호화 checkpoint event는 남아 있을 수 있다.

논문 본 실험으로 확장할 때는 반복 횟수를 30회 이상으로 늘리고, Dropbox-only baseline, 서로 다른 지역의 client 2–5개, 파일 개수 및 replica 수 변화, 장시간 relay 장애 주입을 추가하는 것이 좋다.

## 8. 재현 방법과 원시 결과

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j

python3 benchmarks/run_live_evaluation.py \
  --binary ./build-release/gitvault \
  --repetitions 5 \
  --output results/gitvault-evaluation-YYYYMMDD-release \
  --relay wss://relay.damus.io \
  --relay wss://relay.primal.net \
  --relay wss://relay.ditto.pub

python3 benchmarks/run_controlled_evaluation.py \
  --build build-release \
  --output results/gitvault-evaluation-YYYYMMDD-release \
  --repetitions 5

ctest --test-dir build-release --output-on-failure
```

라이브 스크립트는 Dropbox credential이 이미 설정된 환경을 전제로 한다. 고유한 임시 vault 5개와 무작위 평가용 password를 만들며, 종료 시 생성한 정확한 Dropbox vault와 로컬 메타데이터만 삭제한다. 공용 relay event는 삭제하지 못한다.

이번 실행의 원시 및 요약 결과는 다음 파일에 있다.

- [환경 정보](../results/gitvault-evaluation-20260812-release/environment.json)
- [종단간 원시값](../results/gitvault-evaluation-20260812-release/raw_commands.csv)
- [종단간 요약](../results/gitvault-evaluation-20260812-release/summary_commands.csv)
- [단계별 원시값](../results/gitvault-evaluation-20260812-release/raw_phases.csv)
- [단계별 요약](../results/gitvault-evaluation-20260812-release/summary_phases.csv)
- [Rollback/Fork 원시값](../results/gitvault-evaluation-20260812-release/checkpoint_detection.csv)
- [Rollback/Fork 요약](../results/gitvault-evaluation-20260812-release/checkpoint_detection_summary.csv)
- [통제 프로토콜 원시값](../results/gitvault-evaluation-20260812-release/controlled_protocol_runs.csv)
- [통제 프로토콜 요약](../results/gitvault-evaluation-20260812-release/controlled_protocol_summary.csv)
- [명령 및 relay 로그](../results/gitvault-evaluation-20260812-release/commands.log)

본 보고서에는 최적화되지 않은 예비 실행 결과가 아니라 `gitvault-evaluation-20260812-release`의 Release 결과만 사용했다.

## 참고한 평가 관점

- E.-J. Goh, H. Shacham, N. Modadugu, D. Boneh, *SiRiUS: Securing Remote Untrusted Storage*, NDSS, 2003.
- J. Li, M. Krohn, D. Mazières, D. Shasha, *Secure Untrusted Data Repository (SUNDR)*, OSDI, 2004.
