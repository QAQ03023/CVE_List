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

# ==========================================
# 1. 網頁頁面路由 (確認 HTML 與 app.py 在同層)
# ==========================================

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/cve-list')
def cve_list_page():
    return send_from_directory('.', 'list.html')

# ==========================================
# 2. 儀表板 API 路由
# ==========================================

# 路由：提供首頁圓餅圖統計數據
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

# 路由：獲取首頁右側最新更新的前 5 筆 CVE 漏洞 (解決 404 問題的關鍵！)
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

# ==========================================
# 3. 漏洞清單頁面高階搜尋 API
# ==========================================

# 核心：100% 疏通、防止參數打架、且支援 20-0001 年份補滿的完美複合查詢 API
@app.route('/api/search-advanced')
def advanced_search():
    top_q = request.args.get('top_q', '').strip()      
    cve_id = request.args.get('cve_id', '').strip()    
    risk = request.args.get('risk', '')        
    vendor = request.args.get('vendor', '').strip()    
    product = request.args.get('product', '').strip()  
    desc = request.args.get('desc', '').strip()        

    conn = get_db_connection()
    
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

    # 1. 全域頂部搜尋：資安編號精準底線補滿萬用字元演算法
    if top_q:
        clean_q = top_q
        if top_q.upper().startswith("CVE-"):
            clean_q = top_q[4:] # 剝離 cve- 字頭
            
        if "-" in clean_q:
            parts = clean_q.split("-")
            year_part = parts[0].strip()  # 例如 "20"
            seq_part = parts[1].strip()   # 例如 "0001"
            
            # 如果年份部分不滿 4 位數，我們用 SQL 的 "_" 精準補滿年份到 4 位數
            if len(year_part) < 4:
                needed_underscores = 4 - len(year_part)
                year_part = year_part + ("_" * needed_underscores)  # "20" 自動演變為 "20__"
                
            sql_keyword = f"%{year_part}-{seq_part}%"
        else:
            sql_keyword = f"%{clean_q}%"
            
        query += " AND (cve_id LIKE ? COLLATE NOCASE OR description LIKE ? COLLATE NOCASE)"
        params.extend([sql_keyword, f"%{top_q}%"])

    # 2. 如果頂部搜尋欄是空的，側邊欄組合的 CVE ID 才會生效，杜絕參數衝突
    elif cve_id and cve_id != 'CVE-%-%' and cve_id != 'CVE--':
        clean_cve_id = cve_id
        if cve_id.upper().startswith("CVE-"):
            clean_cve_id = cve_id[4:]
        query += " AND cve_id LIKE ? COLLATE NOCASE"
        params.append(f'%{clean_cve_id}%')

    # 3. 其餘過濾條件（不論用哪種搜尋，都可以疊加過濾）
    if vendor:
        query += " AND vendor LIKE ? COLLATE NOCASE"
        params.append(f'%{vendor}%')
    if product:
        query += " AND product LIKE ? COLLATE NOCASE"
        params.append(f'%{product}%')
    if desc:
        query += " AND description LIKE ? COLLATE NOCASE"
        params.append(f'%{desc}%')

    # 4. 風險等級下拉過濾
    if risk:
        query = f"SELECT * FROM ({query}) WHERE risk_level = ?"
        params.append(risk)
    else:
        # 預設按最後異動時間由新到舊排序
        query += " ORDER BY COALESCE(date_updated, '') DESC, cve_id DESC LIMIT 150"
    
    try:
        results = conn.execute(query, params).fetchall()
        conn.close()
        return jsonify([dict(row) for row in results])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)