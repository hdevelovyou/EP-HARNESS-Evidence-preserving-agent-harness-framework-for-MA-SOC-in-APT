# Hướng dẫn chạy baseline Structured Capsule (B1) với Gemma 4 26B

Baseline chính của EP-HARNESS là **`B1_structured_capsule`**: MA-SOC được yêu cầu xuất Evidence Capsule v0.2 và khối
`evidence_claims` có trích dẫn, nhưng harness **chỉ ghi lại, không can thiệp**. Như vậy, khoảng cách giữa B1 và
EP-HARNESS hoàn chỉnh là phần đóng góp của harness (kiểm, chặn, sửa, điều phối), không lẫn với lợi ích của việc
xuất claim có cấu trúc. Thiết kế đầy đủ: [`experiment_design.md`](experiment_design.md).

| | B1 (baseline) | Không phải baseline |
|---|---|---|
| Capsule + `evidence_claims` | có | |
| Contract Gate | **shadow**: dựng capsule, ghi phán quyết C1–C4/R1–R4, **không chặn, không lọc** | inline (chặn) là `L1_gate` |
| Thẻ bằng chứng | **tắt** | bật là `B1c_structured_capsule_cards` |
| Semantic review | tắt | `L2_semantic` |
| Policy | `fixed` (vòng thử lại MA-SOC, 1 lần) | `adaptive` là `Full_ep_harness` |

> Lưu ý: chỉ đặt `ENABLE_CONTRACT_GATE=true` + `ENABLE_CITED_CLAIMS=true` mà không đặt `CONTRACT_GATE_MODE=shadow`
> thì gate chặn thật và thẻ bằng chứng bật mặc định. Cấu hình đó là **`L1_gate`**, không phải baseline.

---

## 1. Model

Kiểm tra bằng `model_check.py` cho thấy Gemma 4 26B IT trên Google API có định danh `models/gemma-4-26b-a4b-it` và
đang ở trạng thái `READY (Limit > 0)`. `agents/llm_config.py` mặc định dùng model này cho cả 8 vai trò
(coordinator, hunter, verifier, analyst, reporter, tools, debate_feedback, debate_judge). Alias `gemma-4-26b-it`
và `models/gemma-4-26b-it` được tự ánh xạ về `models/gemma-4-26b-a4b-it`.

Đổi model cho **mọi** agent chỉ cần hai biến:

```powershell
$env:AGENT_LLM_PROVIDER = "google"
$env:AGENT_MODEL = "models/gemma-4-26b-a4b-it"
```

Không đặt `HUNTER_MODEL`, `VERIFIER_MODEL`... trong `.env` trừ khi cố ý thử từng vai trò: biến theo vai trò được ưu
tiên hơn `AGENT_MODEL`, nên khi đổi model chung sẽ có agent không đổi theo.

---

## 2. Biến môi trường của baseline

### 2.1. EP-HARNESS

| Biến | Giá trị B1 | Ý nghĩa |
| :--- | :--- | :--- |
| `ENABLE_CONTRACT_GATE` | `true` | Dựng capsule tại các handoff Hunter→Verifier, Verifier→Analyst, Analyst→Reporter, Reporter→output |
| `CONTRACT_GATE_MODE` | `shadow` | Chỉ ghi phán quyết; Verifier OK/FAIL quyết định như MA-SOC; Reporter nhận bài phân tích đã bỏ khối claim và thẻ `[cN]`, không bị giữ lại dòng nào |
| `ENABLE_CITED_CLAIMS` | `true` | Hunter và Analyst xuất khối `evidence_claims` (`event_ids`, `tools`, `parent_claims`, `observables`, `level`) |
| `ENABLE_EVIDENCE_CARDS` | `false` | Không đặt thẻ bằng chứng trước task view |
| `ENABLE_SEMANTIC_VERIFIER` | `false` | Không có phán quyết ngữ nghĩa từng claim |
| `POLICY_MODE` | `fixed` | Vòng thử lại cố định của MA-SOC |
| `MASOC_MAX_RETRIES` | `1` | Một lần gọi lại, đúng paper MA-SOC; cùng ngân sách với `POLICY_TASK_RETRIES=1` |
| `ENABLE_OUTPUT_GUARDRAIL` | `false` | Chưa có |

`CONTRACT_GATE_ANALYST_RETRIES` chỉ có tác dụng ở chế độ `inline`; ở `shadow` không có gì bị chặn nên không dùng.
Che nhãn (technique ID và dấu hiệu giả lập, `MASK_SIMULATION_MARKERS=1`) luôn bật ở mọi cấu hình.

### 2.2. Tầng điều phối MA-SOC (giữ cố định giữa các cấu hình)

| Biến | Giá trị | Ý nghĩa |
| :--- | :--- | :--- |
| `COLLABORATION_STRATEGY` | `hierarchical` | Debate không nằm trong ma trận thí nghiệm |
| `PROMPT_TECHNIQUE` | `role_based_zero_shot` | Giữ cố định giữa các cấu hình |
| `ENABLE_DAG_ORCHESTRATOR` | `true` | Mở rộng phụ thuộc và sắp xếp topo kế hoạch task |
| `ENABLE_IOC_CURATOR` | `true` | Lọc, chuẩn hoá IOC trước Reporter |
| `ENABLE_TTP_RELATIONS_GRAPH` | `true` | Đồ thị quan hệ ATT&CK cho Analyst |
| `ENABLE_MITRE_MAPPER` | `true` | Ứng viên ATT&CK cục bộ trước Reporter |
| `TASK_EVENT_LIMIT` | `120` | Số event tối đa trong mỗi task view |
| `ENABLE_LLM_REASONING_JUDGE` | `false` | Chấm reasoning bằng luật, không gọi judge ngoài |

---

## 3. Chạy

### Cách khuyến nghị: qua bộ chạy thí nghiệm

Bộ chạy đặt **mọi** công tắc tường minh cho từng cấu hình, nên giá trị còn sót trong `.env` hay trong phiên
PowerShell không làm lệch cấu hình.

```powershell
# Xem trước kế hoạch, không gọi model
python -m ep_harness.experiments plan --configs B1_structured_capsule --scenarios S23 --repeats 1

# Chạy thử nhỏ để đếm số lời gọi và thời gian (gọi model thật)
python -m ep_harness.experiments run --configs B1_structured_capsule Full_ep_harness --scenarios S23 --repeats 2 --execute

# Tổng hợp trung bình ± độ lệch chuẩn
python -m ep_harness.experiments summarize --name <tên thí nghiệm>
```

### Chạy tay một lần

```powershell
$env:AGENT_LLM_PROVIDER = "google"
$env:AGENT_MODEL = "models/gemma-4-26b-a4b-it"
$env:COLLABORATION_STRATEGY = "hierarchical"
$env:ENABLE_CONTRACT_GATE = "true"
$env:CONTRACT_GATE_MODE = "shadow"
$env:ENABLE_CITED_CLAIMS = "true"
$env:ENABLE_EVIDENCE_CARDS = "false"
$env:ENABLE_SEMANTIC_VERIFIER = "false"
$env:POLICY_MODE = "fixed"
$env:MASOC_MAX_RETRIES = "1"
$env:ENABLE_OUTPUT_GUARDRAIL = "false"
$env:ENABLE_LLM_REASONING_JUDGE = "false"

python main.py --scenario S23 --strategy hierarchical --run-name S23_B1_structured_capsule
```

Kịch bản dùng trong thí nghiệm: `S07`, `S16`, `S23` (`extracted_scenarios/`). Hai bộ cũ trong `datasets/` không còn dùng.

### Giới hạn của Gemini miễn phí

Hạn mức gói miễn phí tính theo project, xem số thật trong Google AI Studio. Một run gồm nhiều lời gọi (Coordinator,
mỗi task: Hunter theo số tool bắt buộc + 1 lời gọi kết luận, Verifier; rồi Analyst, Reporter), nên nên chạy thử nhỏ
trước để đếm số lời gọi thật rồi mới lên lịch cho cả ma trận.

Khi bị giới hạn theo phút (429), mọi agent tự chờ rồi gọi lại, không tính là một lần retry. Khi hết hạn mức ngày, run
dừng (mã thoát 75) và bộ chạy thí nghiệm dừng theo; hôm sau chạy lại **đúng lệnh cũ với cùng `--name`**, các run đã
xong được bỏ qua. Số lời gọi, token theo model và thời gian chờ nằm trong `eval_report.json` →
`metadata.openai_metrics` (`llm_calls`, `by_model`, `rate_limit`).

---

## 4. Kiểm tra đầu ra

Mỗi run ghi vào `runs/<run_name>_<timestamp>/`:

1. `orchestration_config.json`: xác nhận `enable_contract_gate: true`, `contract_gate_mode: "shadow"`,
   `enable_cited_claims: true`, `enable_evidence_cards: false`, `enable_semantic_verifier: false`,
   `policy_mode: "fixed"`.
2. `ech_ledger.jsonl`: sổ cái append-only (event, artifact, capsule FINDING/VERIFIED/ANALYSIS/REPORT, các quyết định).
3. `ech_inline_audit.json`: phán quyết gate tại từng handoff. Ở shadow vẫn có `REJECTED` / `RETRY_REQUIRED` được
   ghi lại, nhưng task không bị chặn.
4. `ech_measurement.json`: **thước đo dùng chung cho mọi cấu hình** (Unsupported Claim Rate, Reference Validity,
   Provenance, trích dẫn không liên quan ở finding, finding được chuyển tiếp, bài phân tích, báo cáo). So sánh giữa
   các cấu hình dùng file này, không dùng `ech_inline_audit.json`.
5. `label_mask.json`: các nhãn đã che trước runtime.
6. `FINAL_REPORT_SOC.md`: báo cáo cuối, niêm phong trước khi chấm.
7. `eval_report.json`, `reasoning_eval_report.json`: F1 TTP (chấm trên bản che), F1 IOC, reasoning, token và độ trễ.
