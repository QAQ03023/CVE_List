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

# 路由：獲取最新更新的前 5 筆 CVE 漏洞
@app.route('/api/latest-updates')
def get_latest_updates():
    try:
        conn = get_db_connection()
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

# 核心優化：支援複合式進階查詢 API
@app.route('/api/search-advanced')
def advanced_search():
    top_q = request.args.get('top_q', '').strip()      
    cve_id = request.args.get('cve_id', '').strip()    
    risk = request.args.get('risk', '')        
    vendor = request.args.get('vendor', '').strip()    
    product = request.args.get('product', '').strip()  
    desc = request.args.get('desc', '').strip()        

    conn = get_db_connection()
    
    # 動態計算風險等級的分流語法
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

    # === 全域頂部搜尋處理機制 ===
    if top_q:
        # 移去開頭可能打的 CVE- 或 cve- 前綴，取得純號碼
        clean_q = top_q
        if top_q.upper().startswith("CVE-"):
            clean_q = top_q[4:] # 去除前4個字元，例如把 "CVE-2024-00" 變成 "2024-00"
            
        # 允許模糊比對，這樣不論打完整編號或打 2024-00 都能順利命中
        query += " AND (cve_id LIKE ? COLLATE NOCASE OR description LIKE ? COLLATE NOCASE)"
        params.extend([f'%{clean_q}%', f'%{top_q}%'])

    # 如果頂部搜尋欄是空的，才改用側邊欄的 CVE-ID 複合欄位
    elif cve_id and cve_id != 'CVE-%-%':
        clean_cve_id = cve_id
        if cve_id.upper().startswith("CVE-"):
            clean_cve_id = cve_id[4:]
        query += " AND cve_id LIKE ? COLLATE NOCASE"
        params.append(f'%{clean_cve_id}%')

    # === 疊加其餘側邊欄篩選條件 ===
    if vendor:
        query += " AND vendor LIKE ? COLLATE NOCASE"
        params.append(f'%{vendor}%')
    if product:
        query += " AND product LIKE ? COLLATE NOCASE"
        params.append(f'%{product}%')
    if desc:
        query += " AND description LIKE ? COLLATE NOCASE"
        params.append(f'%{desc}%')

    # === 風險等級過濾 ===
    if risk:
        query = f"SELECT * FROM ({query}) WHERE risk_level = ?"
        params.append(risk)
    else:
        # 預設按最後異動時間由新到舊排序
        query += " ORDER BY COALESCE(date_updated, '') DESC, cve_id DESC LIMIT 150"
    
    results = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in results])

if __name__ == '__main__':
    app.run(debug=True, port=5000)