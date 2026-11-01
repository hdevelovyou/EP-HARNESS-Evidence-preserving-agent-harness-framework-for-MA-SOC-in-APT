import os
import time
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Khởi tạo client OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def check_openai_quota():
    print("--- ĐANG QUÉT DANH SÁCH VÀ KIỂM TRA QUOTA OPENAI ---")
    working_models = []
    
    try:
        # Lấy danh sách tất cả các model mà Key này có quyền truy cập
        models = client.models.list()
        
        # Lọc ra các dòng gpt để test cho nhanh, đỡ quét mấy con như whisper hay dall-e
        target_models = [m.id for m in models if "gpt" in m.id]
        
        for model_id in target_models:
            print(f"[*] Đang thử 'gõ cửa': {model_id}...", end=" ", flush=True)
            
            try:
                # Gửi một prompt cực thấp để check quota thực tế
                client.chat.completions.create(
                    model=model_id,
                    messages=[{"role": "user", "content": "hi"}],
                    max_tokens=1
                )
                
                print("✅ READY (Limit > 0)")
                working_models.append(model_id)
                
            except Exception as e:
                err_msg = str(e).lower()
                if "insufficient_quota" in err_msg or "429" in err_msg:
                    print("❌ LIMIT 0 (Hết tiền/Hết quota)")
                elif "model_not_found" in err_msg:
                    print("🚫 KHÔNG HỖ TRỢ (Model ID không tồn tại)")
                elif "permission_denied" in err_msg or "403" in err_msg:
                    print("🚫 CẤM CỬA (Access Denied)")
                else:
                    print(f"⚠️ LỖI: {str(e)[:50]}...")
            
            # OpenAI rate limit cho bậc Free/Tier 1 khá gắt, nên nghỉ tí
            time.sleep(0.5)

    except Exception as e:
        print(f"\n[!] Lỗi kết nối API: {e}")

    print("\n" + "="*45)
    if working_models:
        print("CÁC MODEL OPENAI CÓ THỂ DÙNG NGAY:")
        for wm in working_models:
            print(f" -> {wm}")
    else:
        print("XONG HẲN RỒI CU: Key này hiện không 'vắt' được con GPT nào.")
    print("="*45)

if __name__ == "__main__":
    check_openai_quota()