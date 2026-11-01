import requests
import json

# URL trực tiếp đến file JSON STIX Enterprise mới nhất của MITRE
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def fetch_and_parse_stix():
    print("[*] Đang tải database MITRE STIX (khoảng 30-40MB)...")
    response = requests.get(STIX_URL)
    
    if response.status_code != 200:
        print("❌ Lỗi: Không thể tải dữ liệu từ MITRE.")
        return None

    stix_data = response.json()
    extracted_techniques = []

    print("[*] Bắt đầu gọt dữ liệu theo Schema của Hieu...")
    
    # Duyệt qua toàn bộ các object trong STIX
    for obj in stix_data.get('objects', []):
        # Chúng ta chỉ quan tâm đến các kỹ thuật tấn công (attack-pattern)
        if obj.get('type') == 'attack-pattern':
            
            # Lấy Technique ID (Thường nằm trong external_references)
            technique_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id')
                    break
            
            # Bỏ qua nếu không có ID hợp lệ
            if not technique_id:
                continue

            # Lấy Tactic (nằm trong kill_chain_phases)
            tactics = [phase.get('phase_name') for phase in obj.get('kill_chain_phases', []) 
                       if phase.get('kill_chain_name') == 'mitre-attack']

            # Gọt vào Schema của cu
            technique_data = {
                "technique_id": technique_id,
                "name": obj.get('name', ''),
                "tactic": tactics,
                "platforms": obj.get('x_mitre_platforms', []),
                "description": obj.get('description', ''),
                "detection": obj.get('x_mitre_detection', ''),
                "data_sources": obj.get('x_mitre_data_sources', []),
                "permissions_required": obj.get('x_mitre_permissions_required', []),
                "defense_bypassed": obj.get('x_mitre_defense_bypassed', []),
                "system_requirements": obj.get('x_mitre_system_requirements', []),
                "is_subtechnique": obj.get('x_mitre_is_subtechnique', False)
            }
            
            extracted_techniques.append(technique_data)

    return extracted_techniques

if __name__ == "__main__":
    results = fetch_and_parse_stix()
    
    if results:
        # Lưu ra file JSON
        output_filename = "mitre_knowledge_base.json"
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
            
        print(f"✅ Hoàn tất! Đã trích xuất thành công {len(results)} techniques & sub-techniques.")
        print(f"📂 Dữ liệu đã được lưu vào {output_filename}")
        
        # In thử một sample cho cu xem
        print("\n--- SAMPLE XUẤT RA ---")
        print(json.dumps(results[0], indent=2, ensure_ascii=False))