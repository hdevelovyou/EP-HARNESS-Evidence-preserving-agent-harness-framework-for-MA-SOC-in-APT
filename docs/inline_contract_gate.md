# Contract Gate inline

Trạng thái: **đã cài đặt** (`ep_harness/inline.py`, tích hợp trong `main.py`); test không gọi LLM:
`tests/test_inline_gate.py`. Chưa chạy trên pipeline thật có LLM.

## Bật / tắt

| Biến môi trường | Mặc định | Ý nghĩa |
|---|---|---|
| `ENABLE_CONTRACT_GATE` | `0` | `1` bật gate inline. Tắt thì pipeline chạy y như MA-SOC gốc |
| `CONTRACT_GATE_ANALYST_RETRIES` | `1` | Số lần gọi lại Analyst khi ANALYSIS bị chặn vì lỗi ở cấp claim |

Giá trị toggle được ghi vào `runs/<id>/orchestration_config.json` như mọi toggle khác.

## Hành vi tại từng handoff

| Handoff | Capsule | Khi gate ACCEPTED | Khi gate chặn |
|---|---|---|---|
| Hunter → Verifier | FINDING | Gọi Verifier; phán quyết ghi vào ledger (`verifier`: ACCEPTED / REJECTED) | **Không gọi Verifier.** Danh sách vi phạm thành feedback cho Hunter, tính vào cùng ngân sách retry. Hết retry → task `Gate_Blocked` |
| Verifier → Analyst | VERIFIED (CARRIED toàn bộ claim) | Task vào input của Analyst | Task `Gate_Blocked`, không vào Analyst, không retry Hunter (lỗi không nằm ở Hunter) |
| Analyst → Reporter | ANALYSIS (claim nối với claim VERIFIED qua event chung) | Reporter nhận nguyên văn | Nếu có vi phạm cấp claim: gọi lại Analyst kèm feedback (tối đa `CONTRACT_GATE_ANALYST_RETRIES`). Vẫn bị chặn: **giữ lại** (không chuyển) các dòng có vi phạm; Reporter nhận phần còn lại |
| Reporter → output | REPORT | Chỉ ghi nhận | Chỉ ghi nhận, không hành động (ngoài phạm vi ba handoff chính) |

Nguyên tắc giữ nguyên:
- Gate chỉ kiểm hình thức và tham chiếu; không gọi LLM. Một finding bị gate chặn tiết kiệm một lời gọi Verifier.
- Hành động duy nhất mang tính "ép" là **loại** claim vi phạm; không bao giờ thêm kết luận.
- Lọc không xoá: `analyst_result.md` giữ bản gốc của lần thử cuối, `analyst_result_gated.md` là bản Reporter nhận;
  mọi capsule, kể cả bị chặn, nằm trong `ech_ledger.jsonl`.
- Mỗi lần thử là capsule mới (`attempt`, `supersedes`). FINDING đã qua gate nhưng không có phán quyết Verifier
  (lỗi API) được Policy Orchestrator đóng là UNRESOLVED.

## Output trong `runs/<id>/`

| File | Nội dung |
|---|---|
| `ech_ledger.jsonl` | Ledger append-only: event, artifact tool, capsule, decision |
| `ech_inline_audit.json` | `summary` (validity, provenance, `claim_flow`, kết quả gate), `handoffs` (từng quyết định và hành động), số bản ghi ledger |
| `analyst_result_gated.md` | Chỉ có khi có claim bị giữ lại |
| `soc_hunt_results.json` | Thêm trạng thái `Gate_Blocked` bên cạnh `Verified` / `Failed_Verification` / `Error` |

Bundle trả về từ `_execute_agent_runtime` có thêm khoá `ech_audit`.

## Giới hạn đã biết

- Agent vẫn viết văn bản tự do. Capsule được dựng bằng cách tách dòng: tham chiếu event là `derived`
  (khớp observable), level theo heuristic, không có `observables`. Vì vậy hiện gate inline chủ yếu bắt được:
  event ID bịa (`dangling_event`), thiếu tool bắt buộc (`missing_tool`), output rỗng, ANALYSIS không có cha
  được chấp nhận. Gate sẽ chặt hơn nhiều khi prompt và parser bắt agent xuất capsule có trích ID (việc tiếp theo).
- C4 tính artifact tool của mọi lần thử trong cùng task, không chỉ lần hiện tại.
- Liên kết claim ANALYSIS → claim VERIFIED dựa trên event chung, nên có thể nối thừa với event phổ biến.
- REPORT gần như luôn bị đánh RETRY_REQUIRED/REJECTED vì các dòng tường thuật bị coi là HYPOTHESIS; đó là lý do
  cạnh này mới chỉ ghi nhận.
- `max_retries = 2` trong `main.py` chưa đổi (vấn đề riêng); gate dùng chung ngân sách này.
