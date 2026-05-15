import sqlite3
import requests
import time
import os

# --- 設定 ---
BASE_DIR = './'
DB_NAME = os.path.join(BASE_DIR, './cve_system.db')
FAILED_LIST_FILE = os.path.join(BASE_DIR, './failed_report.txt') # 失敗 ID 純文字紀錄檔
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
API_KEY = "a9169cef-c825-4736-8ba4-7888691444d7" 

def record_failed_id(cve_id):
    """直接以追加(Append)方式將沒跑成功的 CVE ID 寫入純文字檔末尾"""
    with open(FAILED_LIST_FILE, "a", encoding="utf-8") as f:
        f.write(f"{cve_id}\n")

def fetch_nvd_data(cve_id, headers):
    """向 NVD 請求資料"""
    try:
        response = requests.get(NVD_API_URL + cve_id, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            print(f"\n🛑 觸發流量限制 (403)，請稍候或填入 API Key。")
            return "RETRY"
        elif response.status_code == 404:
            # 畫面上維持 \r 動態覆蓋，不中斷進度條
            print(f"ℹ️ NVD 尚未收錄此 ID: {cve_id}                                 ", end="\r")
            record_failed_id(cve_id) # 直接無腦 Append 寫入 
            return None
        else:
            print(f"❌ HTTP 錯誤 {response.status_code}: {cve_id}                     ", end="\r")
            record_failed_id(cve_id)
            return None
    except Exception as e:
        print(f"❌ 網路/系統錯誤 ({cve_id}): {str(e)[:20]}...                      ", end="\r")
        record_failed_id(cve_id)
    return None

def start_patching():
    if not os.path.exists(DB_NAME):
        print(f"❌ 找不到資料庫檔案: {DB_NAME}")
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # 沿用你上次的 SQL 邏輯，不做任何修改
    cursor.execute('''
        SELECT cve_id FROM cve_data 
        WHERE (cvssV2_score IS NULL OR cvssV3_score IS NULL OR cwe_ids IS NULL OR cwe_ids = '')
        AND state = 'PUBLISHED'
        AND cve_id NOT LIKE 'CVE-1999-%'
        AND cve_id NOT LIKE 'CVE-2000-%'
        AND cve_id NOT LIKE 'CVE-2001-%'
        AND cve_id NOT LIKE 'CVE-2002-%'
        AND cve_id NOT LIKE 'CVE-2003-%'
        AND cve_id NOT LIKE 'CVE-2004-%'
        AND cve_id NOT LIKE 'CVE-2026-%'
        AND cve_id LIKE 'CVE-2009-0%'
        ORDER BY cve_id ASC 
    ''')

    targets = cursor.fetchall()

    if not targets:
        print("✅ 目前已無符合條件的缺失資料。")
        conn.close()
        return

    print(f"🔍 找到 {len(targets)} 筆舊年份缺失資料，準備由舊往新補全...")
    headers = {"apiKey": API_KEY} if API_KEY else {}

    success_count = 0
    for (cve_id,) in targets:
        print(f"🔃 正在處理: {cve_id}...", end="\r")
        result = fetch_nvd_data(cve_id, headers)
        
        if result == "RETRY": 
            break
        
        if result and result.get('vulnerabilities'):
            try:
                vuln = result['vulnerabilities'][0]['cve']
                metrics = vuln.get('metrics', {})
                
                # 解析 V3
                v3_node = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30')
                v3_s, v3_v = (v3_node[0]['cvssData']['baseScore'], v3_node[0]['cvssData']['vectorString']) if v3_node else (None, None)
                
                # 解析 V2
                v2_node = metrics.get('cvssMetricV2')
                v2_s, v2_v = (v2_node[0]['cvssData']['baseScore'], v2_node[0]['cvssData']['vectorString']) if v2_node else (None, None)
                
                # 解析 V4
                v4_node = metrics.get('cvssMetricV40')
                v4_s, v4_v = (v4_node[0]['cvssData']['baseScore'], v4_node[0]['cvssData']['vectorString']) if v4_node else (None, None)

                # 解析 CWE
                weaknesses = vuln.get('weaknesses', [])
                cwe_list = [d.get('value') for w in weaknesses for d in w.get('description', []) if d.get('value') and d['value'].startswith('CWE-')]
                cwe_str = ",".join(list(set(cwe_list)))

                # 更新資料庫 (COALESCE 確保不覆蓋現有值)
                cursor.execute('''
                    UPDATE cve_data 
                    SET cvssV2_score = COALESCE(cvssV2_score, ?),
                        cvssV2_vector = COALESCE(cvssV2_vector, ?),
                        cvssV3_score = COALESCE(cvssV3_score, ?),
                        cvssV3_vector = COALESCE(cvssV3_vector, ?),
                        cvssV4_0_score = COALESCE(cvssV4_0_score, ?),
                        cvssV4_0_vector = COALESCE(cvssV4_0_vector, ?),
                        cwe_ids = CASE WHEN (cwe_ids IS NULL OR cwe_ids = '') THEN ? ELSE cwe_ids END
                    WHERE cve_id = ?
                ''', (v2_s, v2_v, v3_s, v3_v, v4_s, v4_v, cwe_str, cve_id))
                
                conn.commit()
                success_count += 1
                # 成功更新時換行印出，保持畫面節奏感
                print(f"✅ {cve_id} 更新成功 (V2: {v2_s}, V3: {v3_s}, V4: {v4_s}, CWE: {cwe_str})")
            except Exception as e:
                # 資料庫更新失敗也直接 Append 進失敗檔
                record_failed_id(cve_id)
                continue
        
        # 流量延遲 (無 Key 延遲較久)
        time.sleep(0.6 if API_KEY else 6)

    conn.close()
    print(f"\n✨ 本次作業結束。成功補全: {success_count} 筆。")

if __name__ == "__main__":
    start_patching()