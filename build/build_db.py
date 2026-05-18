import sqlite3
import os

DB_NAME = 'cve_system.db'

def create_comprehensive_database():
    # 如果檔案已存在，先刪除以確保結構全新
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
        print(f"🗑️ 已移除舊的資料庫檔案: {DB_NAME}")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # 建立 21 欄位的精簡詳細版資料表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_data (
            -- 1. Metadata 基礎資訊
            cve_id TEXT PRIMARY KEY,
            state TEXT,                    -- PUBLISHED, REJECTED
            date_reserved TEXT,            -- 最初預留時間
            date_published TEXT,           -- 正式發布時間
            date_updated TEXT,             -- 最後修改時間
            assigner_short_name TEXT,      -- 分配機構
            
            -- 2. CNA Content 內容
            title TEXT,
            description TEXT,
            
            -- 3. 受影響對象細節
            vendor TEXT,
            product TEXT,
            version_value TEXT,            -- 具體版本號
            version_status TEXT,           -- 狀態 (如: affected)
            
            -- 4. CVSS 分層細節 (已移除 V3.1 獨立欄位)
            cvssV2_score REAL,
            cvssV2_vector TEXT,
            cvssV3_score REAL,             -- 這裡將存放 V3.0 或 V3.1 的整合分數
            cvssV3_vector TEXT,            -- 整合後的向量
            cvssV4_0_score REAL,
            cvssV4_0_vector TEXT,
            
            -- 5. 弱點與參考
            cwe_ids TEXT,
            reference_urls TEXT,
            raw_json TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print(f"✅ 資料庫 [{DB_NAME}] 結構已重建 (共 21 欄)。")

if __name__ == "__main__":
    create_comprehensive_database()