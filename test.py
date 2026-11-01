import itertools
import requests

target_ip = "185.27.134.137"
base_pattern = "baomatweb-{}86{}5{}.web1337.net"

def generate_subdomains():
    chars = "abcdefghijklmnopqrstuvwxyz"
    for p in itertools.product(chars, repeat=5):
        subdomain = base_pattern.format(p[0], p[1], "".join(p[2:]))
        yield subdomain

def check_vhost(subdomain):
    # Gửi request trực tiếp đến IP nhưng đặt Host header là subdomain cần tìm
    url = f"http://{target_ip}"
    headers = {"Host": subdomain}
    
    try:
        # Timeout ngắn để tăng tốc độ quét
        response = requests.get(url, headers=headers, timeout=2)
        
        # Kiểm tra nếu tìm thấy vhost hợp lệ (thường trả về 200 OK)
        if response.status_code == 200:
            print(f"\n[FOUND] Subdomain: {subdomain}")
            print(f"Content: {response.text[:100]}...") # In thử nội dung trang
            return subdomain
    except requests.exceptions.RequestException:
        pass
    return None

def main():
    print(f"Starting Vhost Brute-force on {target_ip}...")
    count = 0
    
    for sub in generate_subdomains():
        count += 1
        # In tiến độ sau mỗi 1000 lần thử
        if count % 1000 == 0:
            print(f"Tried {count} combinations...", end="\r")
            
        result = check_vhost(sub)
        if result:
            # Ghi lại kết quả tìm được vào file
            with open("found_vhost.txt", "a") as f:
                f.write(result + "\n")
            break # Dừng lại khi tìm thấy subdomain hợp lệ theo yêu cầu

if __name__ == "__main__":
    main()