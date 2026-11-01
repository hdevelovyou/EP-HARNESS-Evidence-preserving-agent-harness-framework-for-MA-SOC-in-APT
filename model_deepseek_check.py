import os
import time

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()

api_key = os.getenv("DEEPSEEK_API_KEY")
client = OpenAI(
    api_key=api_key,
    base_url="https://api.deepseek.com",
) if api_key else None


def check_deepseek_quota():
    print("--- ĐANG KIỂM TRA API KEY VÀ QUOTA DEEPSEEK ---")

    if not api_key:
        print("\n[!] Không tìm thấy DEEPSEEK_API_KEY trong file .env")
        print("    Thêm dòng: DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxx")
        return

    working_models = []

    try:
        # Lấy các model mà API key hiện tại có thể nhìn thấy.
        models = client.models.list()
        target_models = sorted(
            model.id for model in models.data if "deepseek" in model.id.lower()
        )

        if not target_models:
            print("[!] Key hợp lệ nhưng API không trả về model DeepSeek nào.")
            return

        print(f"[+] Key đã được xác thực, tìm thấy {len(target_models)} model.\n")

        for model_id in target_models:
            print(f"[*] Đang thử 'gõ cửa': {model_id}...", end=" ", flush=True)

            try:
                # Gửi prompt rất ngắn để kiểm tra khả năng gọi model thực tế.
                client.chat.completions.create(
                    model=model_id,
                    messages=[{"role": "user", "content": "hi"}],
                    max_tokens=8,
                )

                print("✅ READY (Key và quota hoạt động)")
                working_models.append(model_id)

            except Exception as error:
                error_message = str(error).lower()

                if "authentication" in error_message or "401" in error_message:
                    print("🚫 KEY KHÔNG HỢP LỆ (Authentication Failed)")
                elif (
                    "insufficient balance" in error_message
                    or "insufficient_quota" in error_message
                    or "402" in error_message
                ):
                    print("❌ HẾT SỐ DƯ/HẾT QUOTA")
                elif "rate limit" in error_message or "429" in error_message:
                    print("⏳ RATE LIMITED (Thử lại sau)")
                elif "model_not_found" in error_message or "404" in error_message:
                    print("🚫 MODEL KHÔNG KHẢ DỤNG")
                elif "permission" in error_message or "403" in error_message:
                    print("🚫 CẤM CỬA (Permission Denied)")
                else:
                    print(f"⚠️ LỖI: {str(error)[:120]}...")

            time.sleep(0.5)

    except Exception as error:
        error_message = str(error).lower()

        if "authentication" in error_message or "401" in error_message:
            print("\n[!] API key DeepSeek không hợp lệ hoặc đã bị thu hồi.")
        elif "connection" in error_message or "timeout" in error_message:
            print(f"\n[!] Không thể kết nối tới DeepSeek API: {error}")
        else:
            print(f"\n[!] Lỗi khi kiểm tra DeepSeek API: {error}")

    print("\n" + "=" * 48)
    if working_models:
        print("CÁC MODEL DEEPSEEK CÓ THỂ DÙNG NGAY:")
        for model_id in working_models:
            print(f" -> {model_id}")
    else:
        print("CHƯA CÓ MODEL DEEPSEEK NÀO GỌI THÀNH CÔNG.")
    print("=" * 48)


if __name__ == "__main__":
    check_deepseek_quota()
