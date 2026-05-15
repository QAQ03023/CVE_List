from flask import Flask, jsonify, send_from_directory
import sqlite3
import os

app = Flask(__name__)
DB_PATH = os.path.join(os.getcwd(), 'cve_system.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# 路由：提供靜態首頁
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# 路由：提供統計數據 API
@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    # 依照使用者定義邏輯實作全分類統計
    query = '''
    SELECT 
        COUNT(CASE WHEN 
            cvssV4_0_score >= 9.0 OR 
            (cvssV4_0_score IS NULL AND cvssV3_score >= 9.0) 
            THEN 1 END) as critical,
            
        COUNT(CASE WHEN 
            (cvssV4_0_score >= 7.0 AND cvssV4_0_score < 9.0) OR 
            (cvssV4_0_score IS NULL AND cvssV3_score >= 7.0 AND cvssV3_score < 9.0) OR 
            (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 7.0) 
            THEN 1 END) as high,
            
        COUNT(CASE WHEN 
            (cvssV4_0_score >= 4.0 AND cvssV4_0_score < 7.0) OR 
            (cvssV4_0_score IS NULL AND cvssV3_score >= 4.0 AND cvssV3_score < 7.0) OR 
            (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score >= 4.0 AND cvssV2_score < 7.0) 
            THEN 1 END) as medium,

        COUNT(CASE WHEN 
            (cvssV4_0_score >= 0.1 AND cvssV4_0_score < 4.0) OR 
            (cvssV4_0_score IS NULL AND cvssV3_score >= 0.1 AND cvssV3_score < 4.0) OR 
            (cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score < 4.0) 
            THEN 1 END) as low,

        COUNT(CASE WHEN 
            cvssV4_0_score = 0 OR 
            (cvssV4_0_score IS NULL AND cvssV3_score = 0) 
            THEN 1 END) as none_risk,

        COUNT(CASE WHEN 
            cvssV4_0_score IS NULL AND cvssV3_score IS NULL AND cvssV2_score IS NULL 
            THEN 1 END) as unknown
    FROM cve_data
    '''
    stats = conn.execute(query).fetchone()
    conn.close()
    return jsonify(dict(stats))



# 路由：搜尋 API
@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    conn = get_db_connection()
    results = conn.execute(
        "SELECT * FROM cve_data WHERE cve_id LIKE ? OR description LIKE ? LIMIT 50",
        ('%'+query+'%', '%'+query+'%')
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in results])

if __name__ == '__main__':
    app.run(debug=True, port=5000)