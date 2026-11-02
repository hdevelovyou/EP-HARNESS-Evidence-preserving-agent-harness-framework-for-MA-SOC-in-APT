# Evidence claims do agent tự trích (cited claims)

Trạng thái: **đã cài đặt** (`ep_harness/claim_parser.py`, `ep_harness/inline.py`, `prompts/agent_prompts.py`, `main.py`);
test không gọi LLM: `tests/test_cited_claims.py`. Chưa chạy với LLM thật, nên chưa biết model tuân thủ khuôn dạng tốt đến đâu.

## Bật

```bash
ENABLE_CONTRACT_GATE=1 ENABLE_CITED_CLAIMS=1 python main.py ...
```

`ENABLE_CITED_CLAIMS=1` mà không bật gate sẽ báo lỗi ngay khi nạp cấu hình: chỉ có gate inline đọc và kiểm khối claim.
Tắt cờ này thì prompt giữ nguyên như MA-SOC, gate dùng claim suy ra từ văn bản (`derived`).

## Khuôn dạng agent phải xuất

Hunter và Analyst kết thúc câu trả lời bằng **đúng một** khối:

````
```evidence_claims
[{"id": "c1", "text": "...", "level": "OBSERVED", "event_ids": ["event-28"],
  "tools": ["rex_tool"], "observables": ["dfg.exe", "10.10.12.110"]}]
```
````

| Trường | Hunter | Analyst | Ánh xạ sang capsule |
|---|---|---|---|
| `id` | bắt buộc | bắt buộc, khớp thẻ `[cN]` trong văn bản | `claim_id` (`C2`, `2` → `c2`) |
| `text`, `level` | bắt buộc | bắt buộc | giữ nguyên; level viết hoa |
| `event_ids` | event trong task log | event trong evidence | `event_ids` |
| `tools` | tool trong Tool Execution Audit | — | `artifact_ids` của task; tool không chạy thành công → ID không tồn tại → C3 REJECTED |
| `parent_claims` | — | ref claim VERIFIED, dạng `CAP-T7-VERIFIED-a1#c1` | `parent_claims`; `derivation` mặc định theo số cha |
| `observables` | giá trị chép nguyên văn từ event | như Hunter | `observables` → R3 |

Analyst còn phải gắn thẻ `[cN]` ở cuối mỗi dòng phân tích (kể cả dòng bảng). Danh sách claim VERIFIED kèm ref
được đưa vào input của Analyst (`lean_results[].claims`), và hợp đồng được nối vào evidence context của Analyst.

## Parser và gate chia việc thế nào

- Parser (`claim_parser.py`) dễ dãi về hình dạng, không phán xét: JSON → `Claim` với `lineage = "cited"`.
  Thiếu khối hoặc JSON hỏng → không có claim, kèm một ghi chú lỗi.
- Gate quyết định mọi thứ như cũ: ID event/tool/claim cha bịa → C3 REJECTED; observable không có trong event → R3;
  level vượt claim cha mà không có event riêng → R4; thiếu khối → C2 `too_few_claims` + ghi chú `[format]` trong feedback.
- Khi bị chặn, ghi chú `[format]` hoặc vi phạm ở cấp claim cho phép Analyst được gọi lại (`retryable`).

## Analyst → Reporter ở chế độ cited

Reporter nhận phần tường thuật **đã bỏ khối claim và thẻ `[cN]`**. Nếu ANALYSIS bị chặn, các dòng gắn thẻ của claim
vi phạm bị loại trước. `analyst_result.md` giữ nguyên bản gốc (có khối và thẻ). Summarizer nhận output Hunter đã bỏ
khối claim, nên artifact tóm tắt giữ nguyên dạng cũ.

## Thay đổi kèm theo

- `split_tool_audit` dùng `raw_decode`: văn bản nối sau Tool Execution Audit (ví dụ kết luận Debate Judge) không còn
  làm hỏng việc đọc audit (trước đây audit rỗng → C4 sai).
- Adapter shadow (`audit` CLI) tự dùng khối claim nếu output có, ngược lại vẫn suy ra từ văn bản.

## Giới hạn đã biết

- Dòng tường thuật **không gắn thẻ** của Analyst vẫn đến Reporter mà không được kiểm.
- Verifier chưa xuất claim: VERIFIED vẫn mang tiếp (CARRIED) toàn bộ claim của FINDING; Verifier chưa loại claim
  có khai báo (`dropped_claims`).
- Reporter không xuất khối claim (để không đổi định dạng `FINAL_REPORT_SOC.md` mà evaluator đọc); cạnh
  Reporter → output vẫn chỉ ghi nhận.
- Không có bước kiểm ngữ nghĩa: claim trích đúng event nhưng diễn giải sai vẫn qua gate.
- Một FINDING không có khối claim sẽ bị chặn cho đến khi hết retry; nếu model hay quên khối, tỉ lệ `Gate_Blocked`
  sẽ tăng. Cần đo trên run thật trước khi so sánh chất lượng.
