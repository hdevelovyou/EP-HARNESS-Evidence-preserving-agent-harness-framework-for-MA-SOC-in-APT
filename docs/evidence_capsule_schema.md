# Evidence Capsule — đặc tả schema v0.2

Trạng thái: **đã cài đặt** trong `ep_harness/capsule.py`, `ep_harness/gate.py`, `ep_harness/ledger.py`;
bản máy đọc: `ep_harness/schemas/evidence_capsule.v0.2.json`; test: `tests/test_capsule_schema.py`.
Các quy tắc đánh dấu *(đề xuất)* là lựa chọn thiết kế, cần đánh giá thực nghiệm trước khi khẳng định hiệu quả.

## 1. Vai trò

Evidence Capsule là đối tượng duy nhất được đi qua ranh giới giữa hai agent. Agent không bàn giao văn bản tự do
mà bàn giao một tập **claim**, mỗi claim gắn với bằng chứng (event, artifact của tool, hoặc claim của capsule cha).
Capsule chỉ mô tả *hình thức* và *tham chiếu*; việc bằng chứng có thật sự hỗ trợ claim về mặt ngữ nghĩa hay không
thuộc về Verifier và Output Evidence Guardrail, không thuộc schema hay Contract Gate.

## 2. Định nghĩa

Gọi `E` là tập event telemetry trong Evidence Ledger, `A` là tập artifact (mỗi lần chạy tool), `K` là tập capsule đã ghi.

**Capsule** `k = (id, kind, task, src, dst, attempt, supersedes, P, C, D, tools, meta)`:

| Trường | Kiểu | Ý nghĩa |
|---|---|---|
| `schema_version` | `"0.2"` | Phiên bản schema |
| `capsule_id` | `CAP-[A-Za-z0-9_.:-]+` | Định danh duy nhất; nội dung gắn với ID là bất biến (ledger kiểm hash) |
| `kind` | TASK, FINDING, VERIFIED, ANALYSIS, REPORT | Loại handoff, chọn hợp đồng của cạnh |
| `task_id` | chuỗi | Task trong catalog (T1–T30, hoặc REPORT) |
| `source`, `dest` | agent / `output` | Cạnh handoff; phải có trong Contract Registry |
| `attempt` | số nguyên ≥ 1 | Lần thử thứ mấy của cùng task |
| `supersedes` | `capsule_id` \| null | Capsule bị thay thế; có khi và chỉ khi `attempt > 1` |
| `parent_capsules` (P) | danh sách `capsule_id` | Capsule cha mà capsule này dựa vào |
| `claims` (C) | danh sách claim | Nội dung bàn giao |
| `dropped_claims` (D) | danh sách `{ref, reason, note}` | Claim cha **cố ý không mang tiếp**, kèm lý do |
| `tools_used` | danh sách tên tool | Tool agent khai đã dùng |
| `status` | luôn `PROPOSED` | Agent chỉ được đề xuất; trạng thái thật nằm trong ledger |
| `metadata` | object | Thông tin phụ, không dùng để ra quyết định |

**Claim** `c = (cid, text, level, Ev, Ar, Pc, derivation, Obs, ttp, lineage)`:

| Trường | Ý nghĩa |
|---|---|
| `claim_id` | `c1`, `c2`, … duy nhất trong capsule. Tham chiếu toàn cục: `CAP-…#c1` |
| `text` | Mệnh đề của claim, không rỗng |
| `level` | OBSERVED / INFERRED / HYPOTHESIS (mục 3) |
| `event_ids` (Ev ⊆ E) | Event telemetry được trích |
| `artifact_ids` (Ar ⊆ A) | Kết quả tool được trích |
| `parent_claims` (Pc) | Tham chiếu tới claim trong các capsule thuộc P |
| `derivation` | Quan hệ với claim cha: NEW / CARRIED / REFINED / AGGREGATED (mục 4) |
| `observables` (Obs) | Giá trị nguyên văn mà claim dựa vào (domain, IP, hash, đoạn command line…) |
| `ttp_candidates` | ID ATT&CK do agent đề xuất, định dạng `Txxxx[.xxx]` |
| `lineage` | `cited` (agent tự trích ID) / `derived` (harness khớp observable để suy ra) |

Tham chiếu của claim là `refs(c) = Ev ∪ Ar ∪ Pc`. Claim *có neo* (anchored) khi `refs(c) ≠ ∅`.

## 3. Mức nhận thức (level)

| Level | Điều kiện hình thức (gate kiểm) | Diễn giải |
|---|---|---|
| OBSERVED | `|Ev| ≥ 1` (R1) | Nội dung thấy trực tiếp trong event được trích |
| INFERRED | `|Ev| ≥ 1` hoặc `|Pc| ≥ 1` (R1) | Suy ra từ event và/hoặc claim cha đã chấp nhận, không thấy trực tiếp trong một event |
| HYPOTHESIS | không | Giả thuyết; được đi tiếp nhưng **không** được vào báo cáo cuối như phát hiện (R2 trên cạnh REPORT) |

Thứ hạng: HYPOTHESIS < INFERRED < OBSERVED. Điều kiện trên là *cần*, không *đủ*: claim OBSERVED trích một event
không liên quan vẫn qua R1; phát hiện điều đó là việc kiểm tra ngữ nghĩa.

*So với v0.1:* INFERRED trước đây chỉ cần capsule có cha; nay phải trích **claim cha cụ thể**. Điều này cho phép
truy vết từng claim qua handoff thay vì chỉ theo capsule.

## 4. Quan hệ với claim cha (derivation)

| Derivation | Số claim cha tối thiểu | Ý nghĩa |
|---|---|---|
| NEW | 0 (và phải bằng 0) | Claim bắt đầu tại capsule này |
| CARRIED | 1 | Mang tiếp nguyên mệnh đề |
| REFINED | 1 | Thu hẹp, chính xác hoá hoặc sửa claim cha |
| AGGREGATED | 2 | Mệnh đề mới kết hợp nhiều claim cha |

**Quy tắc không khuếch đại (R4)** *(đề xuất)*: đặt `ceil(c) = max rank(level(p))` trên các claim cha `p ∈ Pc`.
Vi phạm khi `rank(level(c)) > ceil(c)` và (`derivation = CARRIED` hoặc `Ev = ∅`). Nghĩa là claim chỉ được mạnh hơn
claim cha khi tự trích thêm event, và claim CARRIED không bao giờ được nâng mức. Hạ mức luôn được phép.

**Claim bị loại** *(đề xuất)*: claim cha không được tham chiếu bởi claim con nào phải hoặc nằm trong `dropped_claims`
với lý do REFUTED / INSUFFICIENT_EVIDENCE / DUPLICATE / OUT_OF_SCOPE, hoặc bị coi là **mất im lặng**.
Lọc có khai báo được ghi lại trong ledger, không xoá; mất im lặng là một dạng suy giảm bằng chứng cần đo.
Hiện gate chỉ kiểm tính hợp lệ của khai báo; việc *bắt buộc* khai báo mọi claim cha chưa bật trên cạnh nào.

## 5. Trạng thái xử lý

Capsule do agent tạo luôn ở `PROPOSED`. Mọi thay đổi trạng thái là một bản ghi `decision` trong ledger
(`from`, `to`, `actor`, `violations`, `detail`); ledger từ chối chuyển trạng thái không hợp lệ.

| Từ | Sang | Ai được quyết định |
|---|---|---|
| PROPOSED | ACCEPTED, RETRY_REQUIRED, REJECTED | `contract_gate` (kiểm tra hình thức) |
| ACCEPTED, REVIEW_REQUIRED | ACCEPTED | `verifier`, `output_guardrail`, `human_analyst` |
| ACCEPTED, REVIEW_REQUIRED | REVIEW_REQUIRED, REJECTED, UNRESOLVED | trên + `policy_orchestrator` |
| RETRY_REQUIRED, REJECTED, UNRESOLVED | — | Trạng thái cuối |

Bất biến:
- Agent không tự ACCEPT: capsule gửi lên với `status ≠ PROPOSED` bị REJECTED (C1).
- Không actor nào quyết định trên capsule do chính mình tạo (`actor ≠ source`).
- Policy Orchestrator chỉ được dừng hoặc chuyển xem xét, không bao giờ ACCEPT (không ép thêm kết luận).
- Thử lại = capsule mới với `attempt + 1` và `supersedes` trỏ về capsule RETRY_REQUIRED cũ, cùng `task_id`, `kind`,
  `source`; mỗi capsule chỉ được thay thế một lần (C3). Capsule cũ vẫn nằm trong ledger.
- `ACCEPTED` sau gate nghĩa là "đạt hình thức"; quyết định ngữ nghĩa tiếp theo được ghi thành decision riêng
  với actor tương ứng, nên luôn phân biệt được hai tầng.

## 6. Ánh xạ sang Contract Gate

| Mã | Kiểm tra trên trường mới | Kết quả khi vi phạm |
|---|---|---|
| C1 | `schema_version`, định dạng `capsule_id`/`claim_id`/tham chiếu, `claim_id` trùng, `derivation` khớp số claim cha, `attempt`/`supersedes`, lý do loại, claim vừa dùng vừa loại | REJECTED |
| C3 | Claim cha tồn tại **và** thuộc capsule trong `parent_capsules`; capsule cha ACCEPTED; chuỗi retry hợp lệ | REJECTED |
| R1 | Neo theo level (mục 3) | RETRY_REQUIRED |
| R3 *(đề xuất)* | Mỗi observable xuất hiện (không phân biệt hoa thường) trong event được trích hoặc trong claim cha | RETRY_REQUIRED |
| R4 *(đề xuất)* | Không khuếch đại level (mục 4) | RETRY_REQUIRED |

C2, C4, R2 giữ nguyên như v0.1. R3 là **neo từ vựng**: nó cho biết giá trị đó thật sự có trong bằng chứng,
không cho biết mệnh đề về giá trị đó đúng. Mọi `GateResult` ghi `semantic_check: not_performed`.

## 7. Đại lượng đo được từ schema

`ep_harness.metrics.claim_flow` tính trên mỗi cạnh handoff `source->dest`:
`parent_claims`, `carried`, `dropped_declared`, `lost_silently`, `child_claims`, `derivation_*`, `escalated`, `downgraded`.
Đây là số đếm cấu trúc; chúng là đầu vào cho việc đo bảo toàn / suy giảm / khuếch đại claim qua từng handoff,
nhưng chưa phải phép đo ngữ nghĩa (claim CARRIED có còn giữ nghĩa không vẫn cần Verifier hoặc judge).

## 8. Ví dụ

```json
{
  "schema_version": "0.2",
  "capsule_id": "CAP-T7-VERIFIED",
  "kind": "VERIFIED",
  "task_id": "T7",
  "source": "verifier",
  "dest": "analyst",
  "attempt": 1,
  "supersedes": null,
  "parent_capsules": ["CAP-T7-FINDING"],
  "claims": [
    {
      "claim_id": "c1",
      "text": "Máy 10.10.12.110 truy vấn DNS compdatasystems.com",
      "level": "OBSERVED",
      "event_ids": ["event-2"],
      "parent_claims": ["CAP-T7-FINDING#c1"],
      "derivation": "CARRIED",
      "observables": ["compdatasystems.com", "10.10.12.110"],
      "lineage": "cited"
    },
    {
      "claim_id": "c2",
      "text": "Tiến trình PowerShell mã hoá là stager liên lạc với C2",
      "level": "INFERRED",
      "parent_claims": ["CAP-T7-FINDING#c1", "CAP-T7-FINDING#c2"],
      "derivation": "AGGREGATED",
      "lineage": "cited"
    }
  ],
  "dropped_claims": [
    {"ref": "CAP-T7-FINDING#c3", "reason": "INSUFFICIENT_EVIDENCE", "note": "không có event lateral movement"}
  ],
  "status": "PROPOSED"
}
```

## 9. Giới hạn đã biết

- Adapter shadow (`adapters/masoc.py`) vẫn sinh claim từ văn bản tự do: level theo heuristic, `lineage = derived`,
  không có `observables`; Verifier của MA-SOC được mô hình hoá là CARRIED toàn bộ claim. Số liệu từ adapter này
  chỉ là cận trên về mức neo.
- Prompt và output parser chưa yêu cầu agent xuất đúng schema này (việc tiếp theo).
- R3 so khớp chuỗi con: observable quá ngắn hoặc quá phổ biến có thể khớp ngẫu nhiên; chưa có ngưỡng độ dài.
