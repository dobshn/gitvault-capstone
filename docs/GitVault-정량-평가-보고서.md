# GitVault 1차 정량 평가 보고서

**측정일:** 2026년 8월 12일

**목적:** GitVault의 주요 파일 연산 지연시간과 Dropbox·Nostr 기반 일관성 프로토콜의 비용을 확인한다.

## 1. 평가 개요

Release 빌드에서 실제 Dropbox와 공용 Nostr relay 3개를 사용해 `init`, `status`, `mkdir`, `add`, `cat`, `remove`를 각 5회 측정했다. 전체 60개 명령이 모두 성공했다.

핵심 결과는 다음과 같다.

- `add` 중앙값은 8 KiB에서 17.458초, 10 MiB에서 19.985초였다.
- `cat` 중앙값은 8 KiB에서 6.445초, 10 MiB에서 9.473초였다.
- 작은 파일의 write에서는 암호화보다 Dropbox HEAD 확인·CAS와 Nostr checkpoint 조회·게시 비용이 더 큰 비중을 차지했다.
- damus relay가 1회 연결에 실패했지만, 나머지 두 relay가 `R=2`를 충족해 명령은 정상 수행됐다.

## 2. 측정 방법

### 2.1 측정 대상 명령어

GitVault는 파일과 디렉터리를 암호화된 object로 저장하고, commit과 HEAD로 Vault의 논리적 상태를 관리한다. 이번 평가에서 측정한 명령어의 역할은 다음과 같다.

| 명령어 | 수행 내용 | Vault 상태 변경 |
|---|---|:---:|
| `init` | 새 Vault와 초기 HEAD를 생성하고 Nostr relay와 초기 checkpoint를 설정한다. | 예 |
| `status` | 로컬 checkpoint, Dropbox HEAD, Nostr checkpoint를 비교해 일관성 상태를 출력한다. | 아니오 |
| `mkdir` | Vault 내에 디렉터리를 만들고 새 commit과 HEAD를 확정한다. | 예 |
| `add` | 로컬 파일을 암호화해 Vault 경로에 추가하고 새 commit과 HEAD를 확정한다. | 예 |
| `cat` | Vault에서 파일을 다운로드하고 복호화해 내용을 출력한다. | 아니오 |
| `remove` | 최신 Vault 상태에서 파일 경로를 제거하고 새 commit과 HEAD를 확정한다. | 예 |

`mkdir`, `add`, `remove`는 Dropbox HEAD를 CAS로 갱신하고 확정된 상태의 signed checkpoint를 Nostr에 게시하는 write 연산이다. `status`와 `cat`은 Vault의 논리적 상태를 변경하지 않는 read-only 연산이다.

### 2.2 실험 환경 및 조건

| 항목 | 설정 |
|---|---|
| 빌드 | CMake Release, `-O3 -DNDEBUG` |
| 장비 | Apple M1 Pro 10-core, RAM 32 GB |
| OS | macOS 26.5.2, arm64 |
| Cloud | 실제 Dropbox, revision 기반 conditional upload(CAS) |
| Nostr | damus, primal, ditto |
| Quorum | write `W=2`, read `R=2`, relay 3개 |
| 반복 | 각 조건 5회 |
| 파일 크기 | 8 KiB, 1 MiB, 10 MiB 무작위 데이터 |

파일 크기는 Vault 전체가 아니라 **파일 하나의 평문 크기**다. 모든 실험 파일은 Vault 루트에 직접 위치했으며, 중첩 경로 탐색 비용은 포함하지 않았다. 각 반복은 `add → cat → remove`로 진행했고, 크기 조건들은 하나의 주 Vault에서 순차적으로 수행했다.

종단간 시간에는 프로세스 시작, Dropbox 인증 준비, KDF·identity 로드, Dropbox 통신, Nostr relay 통신이 모두 포함된다. p95는 5개 표본의 선형 보간값이므로 장기적인 tail latency가 아닌 이번 실행의 기술 통계로 해석한다.

## 3. 측정 결과

### 3.1 종단간 지연시간

단위는 초다.

| 연산 | 크기 | 중앙값 | p95 | 성공 |
|---|---:|---:|---:|---:|
| `init` | - | 10.558 | 11.311 | 5/5 |
| `status` | - | 3.998 | 5.066 | 5/5 |
| `mkdir` | - | 17.849 | 19.235 | 5/5 |
| `add` | 8 KiB | 17.458 | 18.312 | 5/5 |
| `add` | 1 MiB | 17.496 | 18.484 | 5/5 |
| `add` | 10 MiB | 19.985 | 21.592 | 5/5 |
| `cat` | 8 KiB | 6.445 | 8.578 | 5/5 |
| `cat` | 1 MiB | 7.495 | 9.688 | 5/5 |
| `cat` | 10 MiB | 9.473 | 10.544 | 5/5 |
| `remove` | 8 KiB 대상 | 18.178 | 18.445 | 5/5 |
| `remove` | 1 MiB 대상 | 18.975 | 20.386 | 5/5 |
| `remove` | 10 MiB 대상 | 18.293 | 18.856 | 5/5 |

8 KiB 대비 10 MiB에서 `add` 중앙값은 14.5%, `cat`은 47.0% 증가했다. `remove`는 blob 본문을 다시 전송하지 않아 파일 크기에 따른 변화가 크지 않았다.

### 3.2 Add 주요 단계

각 값은 5회 중앙값이며 단위는 ms다.

| 단계 | 8 KiB | 1 MiB | 10 MiB |
|---|---:|---:|---:|
| KDF·identity 로드 | 184.756 | 191.213 | 188.267 |
| write 전 cloud·relay 확인 | 2,444.156 | 2,390.274 | 2,275.806 |
| object 준비·업로드 | 3,647.677 | 3,272.962 | 6,239.755 |
| CAS·readback·checkpoint 확정 | 7,934.107 | 8,605.329 | 8,587.393 |
| **종단간** | **17,458.244** | **17,496.047** | **19,985.272** |

10 MiB에서 object 준비·업로드 비용은 증가했지만, cloud·relay 확인과 CAS·checkpoint 경로에서 파일 크기와 무관한 고정 비용이 크게 나타났다.

### 3.3 Cat 주요 단계

| 단계 | 8 KiB | 1 MiB | 10 MiB |
|---|---:|---:|---:|
| KDF·identity 로드 | 192.000 | 189.875 | 186.072 |
| cloud·relay 확인 | 2,371.223 | 2,802.464 | 2,193.370 |
| commit·tree 경로 해석 | 1,793.378 | 1,747.436 | 1,756.215 |
| blob 다운로드 | 667.641 | 1,142.458 | 3,712.657 |
| blob 복호화·검증 | 0.147 | 10.605 | 78.133 |
| **종단간** | **6,445.467** | **7,495.438** | **9,472.784** |

`cat`에서 파일 크기 증가의 주요 원인은 blob 다운로드였다. 10 MiB blob의 복호화·검증은 78.133 ms로, 전체 `cat` 중앙값의 약 0.82%였다.

### 3.4 Relay 응답

| Relay | EOSE 성공 | 성공 응답 중앙값 |
|---|---:|---:|
| damus | 4/5 | 1,213.5 ms |
| primal | 5/5 | 1,716.0 ms |
| ditto | 5/5 | 1,413.0 ms |

damus에서 1회 WebSocket handshake가 거절됐지만 primal과 ditto가 응답해 모든 `status` 명령이 `CONSISTENT`로 완료됐다.

## 4. 해석 및 한계

이번 측정에서 확인한 핵심 결론은 다음과 같다.

- 작은 파일의 write는 암호화보다 Dropbox CAS와 Nostr quorum을 포함한 원격 일관성 프로토콜 비용의 영향을 더 크게 받았다.
- 파일 크기가 커질수록 `cat`의 blob 다운로드 시간이 증가했다.
- `remove`는 삭제 대상 blob을 재전송하지 않아 파일 크기와 비교적 무관한 지연시간을 보였다.
- relay 1개의 연결 실패 상황에서 `R=2 of 3` 구성이 정상 동작했다.

다만 본 결과는 조건별 5회, 단일 장비·Dropbox 계정·시간대에서 측정한 1차 결과다. 또한 다음 항목은 아직 측정하지 않았다.

- Dropbox-only baseline 대비 GitVault 프로토콜 overhead
- 매 반복마다 새 Vault를 사용한 독립적 파일 크기 비교
- 경로 깊이, 파일 수, directory 폭에 따른 성능
- Quick/Deep Scan의 preflight 포함 전체 시간과 scan 본체 시간
- 서로 다른 지역의 다중 클라이언트 동시 write 성능

후속 평가에서는 반복 횟수를 30회 이상으로 확대하고, 원격 상태 검증과 실제 파일 처리 비용을 분리하며, 경로 깊이·파일 수·다중 클라이언트 조건을 추가할 필요가 있다.

## 참고

- E.-J. Goh et al., *SiRiUS: Securing Remote Untrusted Storage*, NDSS, 2003.
- J. Li et al., *Secure Untrusted Data Repository (SUNDR)*, OSDI, 2004.
