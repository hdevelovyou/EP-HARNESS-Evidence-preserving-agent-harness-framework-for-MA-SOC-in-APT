# Hướng Dẫn Chạy Thực Nghiệm Baseline: MA-SOC với Structured Capsule Đơn Thuần (Non-Semantic Verified, Non-Adaptive)

Tài liệu này hướng dẫn chi tiết cách thiết lập biến môi trường (environment toggles) và chạy thực nghiệm **Baseline chính** cho công trình **EP-HARNESS**:
- **Cấu hình hệ thống:** MA-SOC kết hợp **Structured Evidence Capsule (v0.2)** và **Inline Contract Gate** kiểm tra cấu trúc/tham chiếu tất định (`C1–C4`, `R1–R4`).
- **Không Semantic Verified:** Tắt lớp kiểm chứng ngữ nghĩa nâng cao (`ENABLE_SEMANTIC_VERIFIER=false`, `ENABLE_OUTPUT_GUARDRAIL=false`, `semantic_check="not_performed"`).
- **Không Adaptive:** Chế độ điều phối cố định (`POLICY_MODE=fixed`), không kích hoạt adaptive evidence-triggered policy.
- **Model đồng nhất (Homogeneous LLM):** Toàn bộ 8 thành phần Agent/Tool đều sử dụng `models/gemma-4-26b-a4b-it` (`gemma-4-26b-it`) qua Google GenAI API.

---

## 1. Kết Quả Kiểm Tra Model (`model_check.py`) & Cấu Hình LLM Đồng Nhất

Kết quả chạy `py -3.11 model_check.py` xác nhận model **Gemma 4 26B IT** trên Google API có định danh chính thức là `models/gemma-4-26b-a4b-it` và đang ở trạng thái **`READY (Limit > 0)`**.

Hệ thống đã được cập nhật tại [`agents/llm_config.py`](../../agents/llm_config.py), [`.env`](../../.env) và [`.env.example`](../../.env.example) để đưa toàn bộ 8 vai trò về cùng model:
- `coordinator` $\rightarrow$ `google` / `models/gemma-4-26b-a4b-it`
- `hunter` $\rightarrow$ `google` / `models/gemma-4-26b-a4b-it`
- `verifier` $\rightarrow$ `google` / `models/gemma-4-26b-a4b-it`
- `analyst` $\rightarrow$ `google` / `models/gemma-4-26b-a4b-it`
- `reporter` $\rightarrow$ `google` / `models/gemma-4-26b-a4b-it`
- `tools` (`shared_llm`) $\rightarrow$ `google` / `models/gemma-4-26b-a4b-it`
- `debate_feedback` $\rightarrow$ `google` / `models/gemma-4-26b-a4b-it`
- `debate_judge` $\rightarrow$ `google` / `models/gemma-4-26b-a4b-it`

*(Lưu ý: [`agents/llm_config.py`](../../agents/llm_config.py) đã hỗ trợ alias tự động: nếu bạn truyền `gemma-4-26b-it` hoặc `models/gemma-4-26b-it`, hệ thống tự động ánh xạ về `models/gemma-4-26b-a4b-it`).*

---

## 2. Rà Soát Các Biến Môi Trường (Environment Toggles) Cho Cấu Hình Baseline

Các biến điều khiển được nạp từ [`src/orchestration_toggles.py`](../../src/orchestration_toggles.py), [`agents/llm_config.py`](../../agents/llm_config.py), [`prompts/agent_prompts.py`](../../prompts/agent_prompts.py) và [`main.py`](../../main.py):

### 2.1. Nhóm biến EP-HARNESS (Structured Capsule, Non-Semantic, Non-Adaptive)

| Biến môi trường | Giá trị chuẩn Baseline | Ý nghĩa trong thực nghiệm Baseline |
| :--- | :--- | :--- |
| `ENABLE_CONTRACT_GATE` | `true` (`1`) | Bật `InlineECH` (Inline Contract Gate) tại 3 handoff chính (`Hunter -> Verifier`, `Verifier -> Analyst`, `Analyst -> Reporter`) và ghi nhận tại `Reporter -> output`. Mọi dữ liệu đi qua handoff đều được đóng gói thành **Evidence Capsule v0.2** và kiểm tra quy tắc hình thức/tham chiếu tất định (`C1–C4`, `R1–R4`). |
| `ENABLE_CITED_CLAIMS` | `true` (`1`) | Bắt buộc `Hunter` và `Analyst` sinh khối cấu trúc ````evidence_claims` trích dẫn trực tiếp `event_ids`, `tools`, `parent_claims`, `observables`, `level` (`OBSERVED`/`INFERRED`/`HYPOTHESIS`) và gắn thẻ `[cN]`. *(Nếu muốn chạy biến thể capsule tự suy diễn từ free-text mà không ép prompt sinh JSON block, đặt `ENABLE_CITED_CLAIMS=false`).* |
| `CONTRACT_GATE_ANALYST_RETRIES` | `1` | Số lần cho phép `Analyst` retry khi capsule `ANALYSIS` bị chặn bởi lỗi claim-level hoặc thiếu khối `evidence_claims` trước khi lọc bỏ các dòng vi phạm. |
| `ENABLE_SEMANTIC_VERIFIER` | `false` (`0`) | **Tắt** kiểm chứng ngữ nghĩa sâu (Semantic Evidence Verification). Contract Gate chỉ kiểm tra tính hợp lệ của schema và tham chiếu (`semantic_check: "not_performed"`). |
| `POLICY_MODE` | `fixed` | **Tắt** điều phối thích nghi (`adaptive`). Giữ luồng thực thi và ngân sách retry cố định (`fixed`). |
| `ENABLE_OUTPUT_GUARDRAIL` | `false` (`0`) | **Tắt** Output Evidence Guardrail ở đầu ra cuối. |

### 2.2. Nhóm biến tầng điều phối MA-SOC (Core Orchestration Toggles)

| Biến môi trường | Giá trị chuẩn Baseline | Ý nghĩa |
| :--- | :--- | :--- |
| `COLLABORATION_STRATEGY` | `hierarchical` | Kiến trúc cộng tác phân cấp chuẩn của MA-SOC (`Coordinator -> Hunter <-> Verifier -> Analyst -> Reporter`). |
| `PROMPT_TECHNIQUE` | `role_based_zero_shot` | Kỹ thuật prompt mặc định (có thể đổi sang `chain_of_thought` hoặc `example_based_fewshot` nhưng cần giữ cố định giữa các cấu hình so sánh). |
| `ENABLE_DAG_ORCHESTRATOR` | `true` | Bật mở rộng phụ thuộc và sắp xếp topo cho kế hoạch task CyberTeam DAG. |
| `ENABLE_IOC_CURATOR` | `true` | Bật bộ lọc và chuẩn hóa IOC (`IOCCurator`) trước khi đưa vào `Reporter`. |
| `ENABLE_TTP_RELATIONS_GRAPH` | `true` | Bật đồ thị quan hệ MITRE ATT&CK hỗ trợ suy luận ngang cho `Analyst`. |
| `ENABLE_MITRE_MAPPER` | `true` | Bật truy xuất ứng viên MITRE ATT&CK cục bộ (`MitreMapper`) trước bước `Reporter`. |
| `TASK_EVENT_LIMIT` | `120` | Giới hạn số lượng sự kiện telemetry tối đa truyền vào mỗi task view. |
| `ENABLE_LLM_REASONING_JUDGE` | `false` | Đánh giá hậu kiểm (`ReasoningEvaluator`) dùng bộ chấm điểm tất định (rule-based), không gọi OpenAI judge bên ngoài. |

---

## 3. Thiết Lập Nhanh Trong PowerShell & Lệnh Chạy Thực Nghiệm

### Bước 1: Thiết lập biến môi trường cho phiên PowerShell hiện tại

Copy và chạy khối lệnh dưới đây trong PowerShell tại thư mục gốc của project:

```powershell
# 1. Cấu hình đồng nhất tất cả Agent về Gemma-4-26B-IT
$env:AGENT_LLM_PROVIDER="google"
$env:AGENT_MODEL="models/gemma-4-26b-a4b-it"
$env:AGENT_MODEL_TIMEOUT_SECONDS="300"

# 2. Cấu hình chiến lược cộng tác & kỹ thuật Prompt MA-SOC
$env:COLLABORATION_STRATEGY="hierarchical"
$env:PROMPT_TECHNIQUE="role_based_zero_shot"
$env:TASK_EVENT_LIMIT="120"

# 3. Các thành phần điều phối cốt lõi của MA-SOC
$env:ENABLE_DAG_ORCHESTRATOR="true"
$env:ENABLE_IOC_CURATOR="true"
$env:ENABLE_TTP_RELATIONS_GRAPH="true"
$env:ENABLE_MITRE_MAPPER="true"

# 4. Cấu hình Baseline EP-HARNESS: Structured Capsule đơn thuần (Không Semantic Verified, Không Adaptive)
$env:ENABLE_CONTRACT_GATE="true"
$env:ENABLE_CITED_CLAIMS="true"
$env:CONTRACT_GATE_ANALYST_RETRIES="1"
$env:ENABLE_SEMANTIC_VERIFIER="false"
$env:POLICY_MODE="fixed"
$env:ENABLE_OUTPUT_GUARDRAIL="false"

# 5. Đảm bảo bộ chấm hậu kiểm độc lập không phụ thuộc LLM ngoài
$env:ENABLE_LLM_REASONING_JUDGE="false"
```

### Bước 2: Kiểm tra danh sách kịch bản (Scenarios) hiện có

```powershell
py -3.11 main.py --list-scenarios
```

Các kịch bản có sẵn bao gồm:
- **Extracted APT Scenarios (`extracted_scenarios/`):** `S07`, `S16`, `S23`
- **Legacy Datasets (`datasets/`):** `CobaltStrike_Lockbit`, `Lynx_Ransomware`

### Bước 3: Chạy thực nghiệm trên từng kịch bản

- **Chạy trên kịch bản `S23` (mặc định, nhẹ để smoke test & chạy nhanh):**
  ```powershell
  py -3.11 main.py --scenario S23 --strategy hierarchical --run-name S23_Baseline_StructuredCapsule
  ```

- **Chạy trên kịch bản `S07` hoặc `S16`:**
  ```powershell
  py -3.11 main.py --scenario S07 --strategy hierarchical --run-name S07_Baseline_StructuredCapsule
  py -3.11 main.py --scenario S16 --strategy hierarchical --run-name S16_Baseline_StructuredCapsule
  ```

- **Chạy trên tập dữ liệu `CobaltStrike_Lockbit` hoặc `Lynx_Ransomware`:**
  ```powershell
  py -3.11 main.py --scenario CobaltStrike_Lockbit --strategy hierarchical --run-name CS_Lockbit_Baseline_StructuredCapsule
  py -3.11 main.py --scenario Lynx_Ransomware --strategy hierarchical --run-name Lynx_Baseline_StructuredCapsule
  ```

- **Chạy lặp 5 lần (Multi-run Benchmark theo yêu cầu KLTN):**
  ```powershell
  1..5 | ForEach-Object {
      Write-Host "=== Running Iteration $_ ==="
      py -3.11 main.py --scenario S23 --strategy hierarchical --run-name "S23_Baseline_Capsule_Run$_"
  }
  ```

---

## 4. Kiểm Tra Artifacts Đầu Ra Sau Khi Chạy

Mỗi lần chạy sẽ sinh ra một thư mục độc lập tại `runs/<run_name>_<timestamp>/`. Để xác nhận cấu hình **Structured Capsule Baseline** đã hoạt động đúng, hãy kiểm tra các file sau trong thư mục run:

1. `orchestration_config.json`:
   - Xác nhận `"enable_contract_gate": true`, `"enable_cited_claims": true`, `"enable_semantic_verifier": false`, `"policy_mode": "fixed"`, `"enable_output_guardrail": false`.
2. `ech_ledger.jsonl`:
   - Sổ cái append-only lưu toàn bộ `event`, `artifact`, `capsule` (`FINDING`, `VERIFIED`, `ANALYSIS`, `REPORT`) và các `decision` của `contract_gate` / `verifier`.
3. `ech_inline_audit.json`:
   - Thống kê chi tiết của EP-HARNESS:
     - `claim_source`: `"cited"`
     - `summary.evidence_reference_validity`: Tỷ lệ tham chiếu hợp lệ.
     - `summary.provenance_completeness`: Độ đầy đủ nguồn gốc bằng chứng.
     - `summary.claim_flow`: Thống kê bảo toàn / suy giảm / khuếch đại claim qua từng handoff (`carried`, `dropped_declared`, `lost_silently`, `escalated`, `downgraded`).
     - `handoffs`: Danh sách quyết định (`ACCEPTED`, `RETRY_REQUIRED`, `REJECTED`) tại từng cạnh.
4. `analyst_result.md` và `analyst_result_gated.md` *(nếu có claim bị chặn và lọc bỏ trước khi sang Reporter)*.
5. `FINAL_REPORT_SOC.md`: Báo cáo SOC cuối cùng được niêm phong trước khi chạy Evaluator.
6. `eval_report.json` và `reasoning_eval_report.json`: Kết quả chấm điểm Layer 1 (Entity Recall/Precision/F1), Layer 2 (MITRE TTPs & IOCs Weighted F1 / Jaccard) và Reasoning Quality.
