# GitVault 단일 클라이언트 부하 평가 파일럿

작성일: 2026-08-17 (KST)

## 1. 목적과 범위

1차 실험에서 명령별 종단간 시간과 내부 단계 시간을 확인했으므로, 이번에는 입력 파일 수와 연속 요청을 늘렸을 때 현재 GitVault가 어디에서 한계에 도달하는지 탐색했다.

- GitVault 클라이언트(복제본)는 1개만 사용했다.
- 동시에 실행되는 GitVault 명령은 최대 1개다. 따라서 다중 클라이언트 충돌이나 동기화 성능은 측정하지 않는다.
- Dropbox와 Nostr는 실제로 사용했다. 세 릴레이에서 `R=2`, `W=2`를 적용했으므로 각 명령의 preflight 릴레이 읽기와 `init`의 genesis/checkpoint 릴레이 쓰기가 측정 시간에 포함된다.
- smallfile 3.2로 동일한 크기의 비압축성 파일과 중첩 디렉터리를 만들었다.
- YCSB의 workload 개념만 GitVault 명령으로 매핑했다. 수정 전에는 읽기 전용 C형의 짧은 기준선을, 수정 후에는 C/B/A형을 각각 20회 실행했다.

smallfile은 입력 데이터 생성에 사용했을 뿐 GitVault를 우회해 Dropbox를 직접 측정하지 않는다. 실제 측정 대상은 모두 GitVault CLI 명령이다.

## 2. 재현 가능한 러너

실험 러너는 [`benchmarks/run_single_client_load_evaluation.py`](../benchmarks/run_single_client_load_evaluation.py)다. 러너가 수행하는 작업은 다음과 같다.

1. smallfile로 각 규모의 입력 트리를 생성한다.
2. 고유한 이름의 Vault를 실제 Dropbox와 Nostr 릴레이에 초기화한다.
3. `status`, `list`, `tree`, 표본 `cat`, `quick-scan`, `deep-scan`을 순차 실행한다.
4. 가장 큰 초기화 성공 데이터셋에서 YCSB-C/B/A형 순차 workload를 선택적으로 실행한다.
5. 명령 성공 여부, 종단간 시간, `GITVAULT_BENCH` 단계 시간, attempted throughput과 goodput을 CSV로 저장한다.
6. HTTP 429나 network/TLS 오류가 발생해도 실패를 측정값으로 기록하고 가능한 다음 작업을 계속한다.
7. 종료 시 이 실험이 만든 정확한 Vault만 삭제한다.

디렉터리 수와 총 데이터 크기 실험은 [`benchmarks/run_directory_matrix_evaluation.py`](../benchmarks/run_directory_matrix_evaluation.py)가 위 러너를 조건별로 호출하고 결과를 하나의 `matrix_summary.csv`로 집계한다.

이 파일럿에서 사용한 smallfile revision은 `aa2519de5bf0b3b383db2c31eacbf8ac4328e19c`, GitVault 기준 revision은 `80bd7f3`이다. 429 수정 후 실험은 이 revision에 아직 커밋하지 않은 retry 변경을 적용한 작업 트리에서 실행했다. 실행 조건은 파일당 8 KiB, 스레드 1개, GitVault 명령 동시성 1개, 난수 seed `20260817`이다.

예시 실행은 다음과 같다.

```bash
python3 benchmarks/run_single_client_load_evaluation.py \
  --binary ./build-release/gitvault \
  --smallfile-script /path/to/smallfile/smallfile_cli.py \
  --output results/gitvault-single-client-load-YYYYMMDD \
  --relay wss://relay.damus.io \
  --relay wss://relay.primal.net \
  --relay wss://relay.ditto.pub \
  --file-counts 1,2,5,10 \
  --file-size-kib 8 \
  --read-samples 3 \
  --workload-operations 20
```

## 3. 파일럿 결과

### 3.1 규모 증가

아래 값은 현재 시스템을 밀어 보면서 실행 가능 범위를 찾기 위한 소수 표본이다. 아직 통계적 반복 실험 결과는 아니다.

| 파일 수 | 데이터 크기 | `init` 결과 | `init` 시간 | 후속 명령 결과 |
|---:|---:|---|---:|---|
| 1 | 8 KiB | 성공 | 15.410 s | 모든 명령 성공 |
| 2 | 16 KiB | 성공 | 16.296 s | 재실험에서 모든 명령 성공 |
| 5 | 40 KiB | 실패 | 8.525 s | Dropbox HTTP 429 |
| 10 | 80 KiB | 실패 | 9.728 s | Dropbox HTTP 429 |

10파일은 별도 첫 시도에서도 9.957초 후 동일한 HTTP 429로 실패했다. 반면 2파일 첫 시도의 `init`은 성공했지만 `cat` 다운로드 중 network/TLS 오류가 한 차례 발생했고, 같은 조건의 재실험은 모두 성공했다. 따라서 이 결과를 “정확히 5파일부터 항상 실패한다”는 임계값으로 해석하면 안 된다. 현재 외부 서비스 조건에서 작은 부하 증가만으로도 실패가 관측되었다는 안정성 신호로 보는 것이 타당하다.

성공한 1·2파일 실행의 종단간 시간은 다음과 같다.

| 명령 | 1파일 | 2파일 재실험 |
|---|---:|---:|
| `status` | 4.474 s | 4.566 s |
| `list` | 6.427 s | 7.500 s |
| `tree` | 9.734 s | 9.801 s |
| `cat` | 10.285 s | 10.023 s |
| `quick-scan` | 10.337 s | 10.213 s |
| `deep-scan` | 11.496 s | 11.796 s |

표본 수가 각 1회이므로 이 표에서는 평균이나 p95를 제시하지 않았다. 파일 수가 1개에서 2개로 늘어난 효과보다 인터넷 구간 변동이 더 클 수 있다.

### 3.2 연속 읽기 부하

1파일 Vault에서 YCSB-C형 읽기 2회를 연속 실행했다.

| 항목 | 결과 |
|---|---:|
| 성공/시도 | 2/2 |
| 평균 지연시간 | 10.186 s/op |
| 중앙값 | 10.186 s/op |
| attempted throughput | 0.0982 ops/s |
| goodput | 0.0982 ops/s |

2회뿐이므로 p95/p99는 의미 있는 통계량이 아니다. 이 값의 의미는 현재 프로토콜을 그대로 사용하면 단일 클라이언트의 순차 읽기 처리율이 약 0.1 ops/s 수준이었다는 초기 기준선이다.

### 3.3 시간이 쓰이는 위치

2파일 재실험의 `cat` 10.023초 중 계측된 주요 단계는 다음과 같다.

| 단계 | 시간 |
|---|---:|
| preflight 전체 | 2.791 s |
| └ Nostr relay fetch (`R=2`) | 2.303 s |
| └ Dropbox HEAD fetch | 0.481 s |
| 경로 해석 | 4.988 s |
| blob fetch | 0.596 s |
| 복호화·검증 | 0.00025 s |

smallfile이 만든 파일은 여러 단계의 중첩 디렉터리 아래에 있다. GitVault는 경로의 Tree 객체를 Dropbox에서 순차적으로 읽기 때문에, 이 실험에서는 암호 연산보다 경로 해석과 Nostr preflight가 훨씬 큰 비용으로 나타났다.

## 4. 수정 전 부하 실험에서 드러난 병목

5파일과 10파일 `init`은 Dropbox의 `too_many_write_operations` 응답으로 실패했다. 코드와 로그를 함께 보면 원인은 다음 경로로 좁혀진다.

- VaultEngine은 blob 업로드를 3개 작업 스레드로 수행한다([`vault_engine.cpp`](../src/vault_engine.cpp#L657), [`vault_engine.cpp`](../src/vault_engine.cpp#L746)).
- 객체 저장은 존재하지 않을 때만 쓰는 conditional upload를 사용한다([`object_store.cpp`](../src/object_store.cpp#L383)).
- 일반 `put`에는 HTTP 429 재시도와 backoff가 있었지만, 수정 전 conditional upload에는 409 처리만 있고 429 재시도가 없었다.

따라서 이번 파일럿의 가장 중요한 결과는 단순 지연시간 증가가 아니라, 작은 메타데이터 중심 데이터셋에서도 conditional upload가 Dropbox 쓰기 제한을 만나면 `init` 전체가 즉시 실패할 수 있다는 점이다.

## 5. 429 처리 수정

conditional upload의 CAS 의미와 409 충돌 처리는 그대로 유지하면서 다음 정책을 추가했다.

- 최대 5번만 시도하는 bounded retry
- Dropbox `Retry-After` 응답 헤더 우선 적용
- 헤더가 없을 때 JSON 본문의 `error.retry_after` 사용
- 둘 다 사용할 수 없을 때 1, 2, 4, 8초 exponential backoff
- 마지막 429까지 실패하면 원래처럼 명령 실패 처리

구현은 [`dropbox_storage.cpp`](../src/dropbox_storage.cpp#L310)와 [`dropbox_retry.cpp`](../src/dropbox_retry.cpp)에 있으며, 정책 단위 테스트는 [`dropbox_retry_test.cpp`](../tests/dropbox_retry_test.cpp)에 추가했다. Dropbox도 429에서 `Retry-After`를 따르고 값이 없으면 exponential backoff를 사용하도록 권고한다([Dropbox Error Handling Guide](https://developers.dropbox.com/error-handling-guide), [Dropbox Performance Guide](https://developers.dropbox.com/dbx-performance-guide)). 새 테스트를 포함한 전체 12개 테스트가 통과했다.

## 6. 수정 후 재측정

### 6.1 파일 수 증가

수정 전과 같은 1·2·5·10파일 조건을 한 번씩 다시 실행했다.

| 파일 수 | `init` | `cat` | `deep-scan` | 성공한 명령/시도 |
|---:|---:|---:|---:|---:|
| 1 | 15.857 s | 9.906 s | 10.528 s | 7/7 |
| 2 | 16.469 s | 9.807 s | 12.518 s | 7/7 |
| 5 | 17.692 s | 10.485 s | 15.343 s | 7/7 |
| 10 | 19.059 s | 10.817 s | 20.457 s | 7/7 |

수정 전 실패했던 5파일과 10파일 `init`에서 이번에도 각각 429가 한 번 발생했다. 두 요청 모두 1초를 기다린 뒤 두 번째 시도에서 성공했다. 별도의 10파일 workload 실행에서도 `init` 중 429 한 번을 같은 방식으로 회복했다. 즉, 이번 성공은 우연히 429가 발생하지 않은 결과가 아니라 추가한 retry 경로가 실제로 동작한 결과다.

`init`은 1파일 15.857초에서 10파일 19.059초로 증가했다. `deep-scan`은 모든 blob을 읽고 검증하므로 10.528초에서 20.457초로 증가했지만, 표본 `cat`은 파일 수보다 경로 깊이와 WAN 변동의 영향을 받아 약 10초 수준을 유지했다.

### 6.2 YCSB형 순차 workload

10파일 Vault에서 각 workload를 20회 실행했다. 모든 수치는 단일 클라이언트, 동시 명령 1개이며 실제 Dropbox와 Nostr `R=2/W=2`를 포함한다.

| workload | 구성 | 성공 | 평균 | 중앙값 | p95 | goodput |
|---|---|---:|---:|---:|---:|---:|
| YCSB-C형 | read 20 | 20/20 | 9.832 s | 9.925 s | 10.313 s | 0.1017 ops/s |
| YCSB-B형 | read 19, update 1 | 20/20 | 10.860 s | 9.895 s | 13.229 s | 0.0921 ops/s |
| YCSB-A형 | read 10, update 10 | 20/20 | 17.412 s | 17.752 s | 25.773 s | 0.0574 ops/s |

작업 종류별 평균은 읽기 9.832~10.129초, 갱신 24.694~25.132초였다. 갱신 비율이 커질수록 처리율이 낮아진 이유다. A형 갱신에서 계측된 상위 단계 평균은 object 준비·업로드 8.935초, CAS 및 checkpoint finalize 10.184초였다. 읽기 전용 C형에서는 preflight 3.045초, 중첩 경로 해석 4.410초, blob fetch 0.746초가 평균적으로 소요됐다.

## 7. 디렉터리 수와 총 데이터 크기 실험

### 7.1 디렉터리 수

파일 수 20개, 파일당 8 KiB, 총 160 KiB를 고정하고 smallfile의 파일 배치를 바꿨다. 모든 조건에서 각 명령은 한 번씩 실행했으며 7개 명령이 모두 성공했다.

| 실제 디렉터리 수 | 429 retry | `init` | `tree` | `cat` | `quick-scan` | `deep-scan` |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 3 | 21.678 s | 11.518 s | 9.733 s | 14.743 s | 29.090 s |
| 7 | 4 | 26.818 s | 11.165 s | 9.459 s | 15.964 s | 32.665 s |
| 23 | 0 | 40.334 s | 26.681 s | 11.035 s | 29.120 s | 45.623 s |

4개에서 23개로 디렉터리를 늘리자 `init`은 1.86배, `tree`는 2.32배, `quick-scan`은 1.98배, `deep-scan`은 1.57배가 됐다. 반면 임의 파일 하나만 읽는 `cat`은 1.13배였다. 파일 수와 데이터 바이트가 같아도 디렉터리가 늘면 암호화·업로드해야 하는 Tree 객체와 scan 시 방문할 Tree 객체가 증가하기 때문이다.

23개 조건에서는 429 retry가 없었는데도 `init`이 가장 느렸다. 따라서 이 조건의 증가분을 429 대기만으로 설명할 수 없으며, 디렉터리 메타데이터 자체가 GitVault 성능에 중요한 변수임을 확인했다.

### 7.2 총 데이터 크기

파일 수 10개, 실제 디렉터리 수 4개를 고정하고 파일당 크기를 8 KiB, 256 KiB, 4 MiB로 바꿨다. 총 데이터 크기는 각각 80 KiB, 2.5 MiB, 40 MiB다. 이 실험도 모든 조건에서 7/7 명령이 성공했다.

| 총 데이터 크기 | 파일당 크기 | 429 retry | `init` | `cat` | `deep-scan` |
|---:|---:|---:|---:|---:|---:|
| 80 KiB | 8 KiB | 1 | 18.614 s | 9.799 s | 19.644 s |
| 2.5 MiB | 256 KiB | 2 | 17.744 s | 9.730 s | 20.790 s |
| 40 MiB | 4 MiB | 1 | 19.350 s | 10.592 s | 27.013 s |

80 KiB에서 40 MiB로 데이터가 512배 증가했지만 `init`은 1.04배, 단일 파일 `cat`은 1.08배, 모든 blob을 읽는 `deep-scan`은 1.38배가 됐다. 현재 범위에서는 고정적인 Nostr/Dropbox 왕복과 Tree 조회 비용이 크기 때문에 전송량 증가가 종단간 시간에 그대로 비례하지 않았다.

`cat`의 blob 복호화·검증은 8 KiB에서 0.484 ms, 4 MiB에서 47.830 ms로 증가했다. 그러나 4 MiB `cat` 전체는 10.592초였으므로 여전히 암호 연산보다 preflight 3.277초, 경로 해석 4.495초, blob fetch 1.271초의 영향이 훨씬 컸다. `deep-scan`은 전체 40 MiB를 처리하므로 총 크기 증가가 더 분명하게 나타났다.

각 조건이 1회뿐이고 public relay 및 Dropbox WAN 변동과 429 retry 횟수가 서로 다르므로, 수치는 경향을 찾는 파일럿으로 해석해야 한다.

## 8. 해석과 다음 실험

이번 수정으로 429가 발생하더라도 작은 규모의 초기화와 60회의 혼합 workload를 중단 없이 완료할 수 있었다. 현재 측정에서 중요한 성능 특성은 다음과 같다.

- 단일 파일 읽기도 약 10초이며 암호 연산보다 Nostr/Dropbox 네트워크 왕복과 중첩 Tree 경로 해석이 지배적이다.
- 갱신은 약 25초로 읽기의 약 2.5배이며 객체 업로드와 CAS/checkpoint 단계가 큰 비중을 차지한다.
- 파일 수 증가에 따라 `deep-scan` 비용은 명확히 증가한다.
- retry는 실패를 성공으로 바꾸지만 429와 대기시간을 없애지는 않는다. 규모를 더 키우면 업로드 동시성 조절이나 Dropbox batch/upload-session 방식도 검토해야 한다.

다음 본 실험에서는 1, 10, 100, 1,000파일을 각 5회 이상 반복하고 성공률, retry 횟수, 총 retry 대기시간, 중앙값과 p95를 함께 비교한다. 파일 수와 파일 크기를 별도 변수로 두고, 루트 파일과 중첩 경로 파일도 분리해야 한다. 또한 이번 workload는 C→B→A 순서로 실행되어 Nostr checkpoint 이력이 뒤쪽 workload일수록 더 길다. workload 순서를 무작위화하거나 각 workload마다 새 Vault를 사용해야 혼합비 자체의 효과를 더 정확히 분리할 수 있다.

이 설계는 계속 단일 클라이언트만 사용한다. 다만 GitVault 명령 자체가 수행하는 Nostr 읽기와 쓰기는 실제 오버헤드의 일부이므로 그대로 포함한다.

## 9. 원시 결과

- [1파일 및 YCSB-C형 읽기 결과](../results/gitvault-single-client-load-pilot-1file-20260817/)
- [2파일 성공 재실험](../results/gitvault-single-client-load-pilot-2files-r2-20260817/)
- [2파일 network/TLS 실패가 포함된 첫 시도](../results/gitvault-single-client-load-pilot-2files-20260817/)
- [5파일 HTTP 429 결과](../results/gitvault-single-client-load-pilot-5files-20260817/)
- [10파일 HTTP 429 재실험](../results/gitvault-single-client-load-pilot-10files-r2-20260817/)
- [retry 수정 후 1·2·5·10파일 결과](../results/gitvault-single-client-load-postretry-scale-20260817/)
- [retry 수정 후 10파일 C/B/A workload 결과](../results/gitvault-single-client-load-postretry-workloads-20260817/)
- [디렉터리 수·총 크기 매트릭스 결과](../results/gitvault-directory-size-matrix-20260817/)

각 완료 결과 디렉터리에는 `environment.json`, `datasets.csv`, `raw_commands.csv`, `raw_phases.csv`, `scale_summary.csv`, `phase_summary.csv`, `workload_summary.csv`, `commands.log`, smallfile JSON이 저장된다.
