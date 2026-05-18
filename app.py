import sqlite3
import os
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, './cve_system.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# 路由：提供靜態首頁
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# 路由：跳轉到 CVE 清單頁面
@app.route('/cve-list')
def cve_list_page():
    return send_from_directory('.', 'list.html')

# 路由：提供統計數據 API
@app.route('/api/stats')
def get_stats():
    try:
        conn = get_db_connection()
        query = '''
        SELECT 
            COUNT(CASE WHEN cvssV4_0_score >= 9.0 OR (cvssV4_0_score IS NULL AND cvssV3_score >= 9.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 9.0) THEN 1 END) as critical,
            COUNT(CASE WHEN (cvssV4_0_score >= 7.0 AND cvssV4_0_score < 9.0) OR (cvssV4_0_score IS NULL AND cvssV3_score >= 7.0 AND cvssV3_score < 9.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 7.0) THEN 1 END) as high,
            COUNT(CASE WHEN (cvssV4_0_score >= 4.0 AND cvssV4_0_score < 7.0) OR (cvssV4_0_score IS NULL AND cvssV3_score >= 4.0 AND cvssV3_score < 7.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 4.0 AND cvssV2_score < 7.0) THEN 1 END) as medium,
            COUNT(CASE WHEN (cvssV4_0_score >= 0.1 AND cvssV4_0_score < 4.0) OR (cvssV4_0_score IS NULL AND cvssV3_score >= 0.1 AND cvssV3_score < 4.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score < 4.0 AND cvssV2_score >= 0.1) THEN 1 END) as low,
            COUNT(CASE WHEN cvssV4_0_score = 0 OR cvssV4_0_score = 0.0 OR (cvssV4_0_score IS NULL AND (cvssV3_score = 0 OR cvssV3_score = 0.0)) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND (cvssV2_score = 0 OR cvssV2_score = 0.0)) THEN 1 END) as none_risk,
            COUNT(CASE WHEN cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score IS NULL THEN 1 END) as unknown
        FROM cve_data
        '''
        stats = conn.execute(query).fetchone()
        conn.close()
        return jsonify({
            "critical": stats['critical'],
            "high": stats['high'],
            "medium": stats['medium'],
            "low": stats['low'],
            "none_risk": stats['none_risk'],
            "unknown": stats['unknown']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 新增路由：獲取最新更新的前 5 筆 CVE 漏洞
@app.route('/api/latest-updates')
def get_latest_updates():
    try:
        conn = get_db_connection()
        # 依據最後修改時間由新到舊排序，取前 5 筆
        query = '''
            SELECT cve_id, date_updated, cvssV4_0_score, cvssV3_score, cvssV2_score, assigner_short_name 
            FROM cve_data 
            ORDER BY COALESCE(date_updated, '') DESC, cve_id DESC 
            LIMIT 5
        '''
        rows = conn.execute(query).fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 路由：分頁 CVE 清單 API (從新排到舊，每頁 20 筆)
@app.route('/api/cves')
def get_cves_pagination():
    try:
        page = int(request.args.get('page', 1))
        per_page = 20
        offset = (page - 1) * per_page
        
        # 接收前端傳來的篩選參數
        search_query = request.args.get('q', '').strip()
        severities = request.args.get('severities', '') # 逗號分隔的字串，例如: "critical,high"
        
        # 基礎 SQL 語法
        where_clauses = []
        params = []
        
        # 1. 處理嚴格關鍵字搜尋 (不區分大小寫，精準匹配 cve_id)
        if search_query:
            where_clauses.append("LOWER(cve_id) = LOWER(?)")
            params.append(search_query)
            
        # 2. 處理側邊風險等級篩選 (嚴格遵循 V4 > V3 > V2 優先級邏輯)
        if severities:
            severity_list = severities.split(',')
            sev_conditions = []
            
            # 定義每個風險等級在 SQL 中的判定邏輯
            sev_map = {
                "critical": "(cvssV4_0_score >= 9.0 OR (cvssV4_0_score IS NULL AND cvssV3_score >= 9.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 9.0))",
                "high": "((cvssV4_0_score >= 7.0 AND cvssV4_0_score < 9.0) OR (cvssV4_0_score IS NULL AND cvssV3_score >= 7.0 AND cvssV3_score < 9.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 7.0))",
                "medium": "((cvssV4_0_score >= 4.0 AND cvssV4_0_score < 7.0) OR (cvssV4_0_score IS NULL AND cvssV3_score >= 4.0 AND cvssV3_score < 7.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 4.0 AND cvssV2_score < 7.0))",
                "low": "((cvssV4_0_score >= 0.1 AND cvssV4_0_score < 4.0) OR (cvssV4_0_score IS NULL AND cvssV3_score >= 0.1 AND cvssV3_score < 4.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score < 4.0 AND cvssV2_score >= 0.1))",
                "none_risk": "(cvssV4_0_score = 0 OR cvssV4_0_score = 0.0 OR (cvssV4_0_score IS NULL AND (cvssV3_score = 0 OR cvssV3_score = 0.0)) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND (cvssV2_score = 0 OR cvssV2_score = 0.0)))",
                "unknown": "(cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score IS NULL)"
            }
            
            for sev in severity_list:
                if sev in sev_map:
                    sev_conditions.append(sev_map[sev])
            
            if sev_conditions:
                where_clauses.append(f"({' OR '.join(sev_conditions)})")

        # 組合 WHERE 子句
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        conn = get_db_connection()
        
        # 計算篩選後的總筆數
        count_query = f"SELECT COUNT(*) FROM cve_data {where_sql}"
        total_count = conn.execute(count_query, params).fetchone()[0]
        
        # 撈取分頁資料
        data_query = f'''
            SELECT * FROM cve_data 
            {where_sql}
            ORDER BY COALESCE(date_published, '') DESC, cve_id DESC 
            LIMIT ? OFFSET ?
        '''
        # 分頁參數必須加在最後面
        rows = conn.execute(data_query, params + [per_page, offset]).fetchall()
        conn.close()

        return jsonify({
            "page": page,
            "per_page": per_page,
            "total_items": total_count,
            "total_pages": (total_count + per_page - 1) // per_page if total_count > 0 else 1,
            "data": [dict(row) for row in rows]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/search-advanced')
def advanced_search():
    top_q = request.args.get('top_q', '').strip()      # 頂部全域關鍵字
    cve_id = request.args.get('cve_id', '').strip()    # 側邊欄組合的 CVE ID
    risk = request.args.get('risk', '')        # 風險等級
    vendor = request.args.get('vendor', '').strip()    # 廠商
    product = request.args.get('product', '').strip()  # 軟體
    desc = request.args.get('desc', '').strip()        # 敘述關鍵字

    conn = get_db_connection()
    
    # 基礎 SQL 查詢語句與風險等級定義
    query = """
        SELECT *, 
               COALESCE(cvssV4_0_score, cvssV3_score, cvssV2_score) as cvss_score,
               CASE 
                   WHEN cvssV4_0_score >= 9.0 OR (cvssV4_0_score IS NULL AND cvssV3_score >= 9.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 9.0) THEN 'CRITICAL'
                   WHEN cvssV4_0_score >= 7.0 OR (cvssV4_0_score IS NULL AND cvssV3_score >= 7.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 7.0) THEN 'HIGH'
                   WHEN cvssV4_0_score >= 4.0 OR (cvssV4_0_score IS NULL AND cvssV3_score >= 4.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 4.0) THEN 'MEDIUM'
                   WHEN cvssV4_0_score > 0.0 OR (cvssV4_0_score IS NULL AND cvssV3_score > 0.0) OR (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score > 0.0) THEN 'LOW'
                   ELSE 'UNKNOWN'
               END as risk_level
        FROM cve_data 
        WHERE 1=1
    """
    params = []

    # === 【關鍵優化核心】全域搜尋防呆機制 ===
    if top_q:
        # 1. 為了防止資料庫欄位名稱（有些存 "CVE-2024-xxx"，有些只存 "2024-xxx"）格式不一
        # 我們做雙向防防呆：如果使用者輸入帶有 "cve-" 或 "CVE-"，我們同時幫他準備一份「去掉 CVE-」的關鍵字
        clean_q = top_q
        if top_q.upper().startswith("CVE-"):
            clean_q = top_q[4:] # 切割掉前4個字元，變成 "2024-38472"
            
        # 2. 讓 SQL 同時去撈原本的輸入、去掉字頭的輸入、以及描述
        query += """ AND (
            cve_id LIKE ? COLLATE NOCASE OR 
            cve_id LIKE ? COLLATE NOCASE OR 
            description LIKE ? COLLATE NOCASE
        )"""
        params.extend([f'%{top_q}%', f'%{clean_q}%', f'%{top_q}%'])

    # 2. 側邊欄 CVE ID 處理 (若有輸入年份或序號)
    if cve_id and cve_id != 'CVE-%-%':
        # 同樣做雙向容錯
        clean_cve_id = cve_id
        if cve_id.upper().startswith("CVE-"):
            clean_cve_id = cve_id[4:]
        query += " AND (cve_id LIKE ? COLLATE NOCASE OR cve_id LIKE ? COLLATE NOCASE)"
        params.extend([cve_id, clean_cve_id])

    # 3. 側邊欄 廠商過濾
    if vendor:
        query += " AND vendor LIKE ? COLLATE NOCASE"
        params.append(f'%{vendor}%')

    # 4. 側邊欄 軟體過濾
    if product:
        query += " AND product LIKE ? COLLATE NOCASE"
        params.append(f'%{product}%')

    # 5. 側邊欄 描述過濾
    if desc:
        query += " AND description LIKE ? COLLATE NOCASE"
        params.append(f'%{desc}%')

    # 6. 風險等級收縮過濾
    if risk:
        query = f"SELECT * FROM ({query}) WHERE risk_level = ?"
        params.append(risk)
    else:
        # 預設依更新時間排序，限制回傳上限防卡死
        query += " ORDER BY date_updated DESC LIMIT 150"
    
    results = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in results])

if __name__ == '__main__':
    app.run(debug=True, port=5000)