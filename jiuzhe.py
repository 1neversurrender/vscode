labro510 = ['jiuzhe','xiangxing',1,5]
for name in labro510:
    print(name)
print('believe yourself')
# 为佛教拉萨解放拉萨发
# aslgjzskljgas
# 导入必要的库  
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify  from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user  
from werkzeug.security import generate_password_hash, check_password_hash  
import sqlite3  
  
# 初始化Flask应用  
app = Flask(__name__)  

app.config['SECRET_KEY'] = 'your_secret_key'  # 用于会话加密的密钥  
  
# 初始化登录管理器  
login_manager = LoginManager(app)  
login_manager.login_view = 'login'  # 如果用户未登录，重定向到登录页面  
  
# 数据库连接  
def get_db_connection():  
    
    conn = sqlite3.connect('app.db')  
    .row_factory = sqlite3.Row  # 使用Row对象，方便访问列名  
    return conn  
  
# 用户模型  
class User(UserMixin):  
    def __init__(self, id, username, password):  
        self.id = id  
        self.username = username  
        self.password = password  
  
    @staticmethod  
    def get_by_username(username):  
        conn = get_db_connection()  
        cursor = conn.cursor()  
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))  
        user = cursor.fetchone()  
        conn.close()  
        if user:  
            return User(user['id'], user['username'], user['password'])  
        return None  
  
    @staticmethod  
    def get_by_id(user_id):  
        conn = get_db_connection()  
        cursor = conn.cursor()  
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))  
        user = cursor.fetchone()  
        conn.close()  
        if user:
            return User(user['id'], user['username'], user['password'])  
        return None  
  
# 设置加载用户的回调函数  
@login_manager.user_loader  
def load_user(user_id):  
    return User.get_by_id(user_id)  
  
# 注册路由  
@app.route('/')  
@app.route('/home')  
def home():  
    articles = []  
    conn = get_db_connection()  
    cursor = conn.cursor()  
    cursor.execute('SELECT * FROM articles')  
    articles = cursor.fetchall()  
    conn.close()  
    return render_template('home.html', articles=articles)  
  
# 注册页面  
@app.route('/register', methods=['GET', 'POST'])  
def register():  
    if request.method == 'POST':  
        username = request.form['username']  
        password = generate_password_hash(request.form['password'], method='sha256')  
          
        conn = get_db_connection()  
        cursor = conn.cursor()  
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))  
        conn.commit()  
        conn.close()  
          
        flash('注册成功！请登录。', 'success')  
        return redirect(url_for('login'))  
    return render_template('register.html')  
  
# 登录页面  
@app.route('/login', methods=['GET', 'POST'])  
def login():  
    if request.method == 'POST':  
        username = request.form['username']  
        password = request.form['password']  
          
        user = User.get_by_username(username)  
        if user and check_password_hash(user.password, password):  
            login_user(user)  
            flash('登录成功！', 'success')  
            return redirect(url_for('home'))  
        else:  
            flash('用户名或密码错误。', 'danger')  
    return render_template('login.html')  
  
# 登出页面  
@app.route('/logout')  
def logout():  
    logout_user()  
    flash('已登出。', 'info')  
    return redirect(url_for('home'))  
  
# 添加文章页面  
@app.route('/add_article', methods=['GET', 'POST'])  
@login_required  
def add_article():  
    if request.method == 'POST':  
        title = request.form['title']  
        content = request.form['content']  
          
        conn = get_db_connection()  
        cursor = conn.cursor()  
        cursor.execute('INSERT INTO articles (title, content, author_id) VALUES (?, ?, ?)', (title, content, current_user.id))  
        conn.commit()  
        conn.close()  
          
        flash('文章添加成功！', 'success')  
        return redirect(url_for('home'))  
    return render_template('add_article.html')  
  
# API端点：获取所有文章（JSON格式）  
@app.route('/api/articles', methods=['GET'])  
def get_articles():  
    articles = []  
    conn = get_db_connection()  
    conn = get_db_connection()  

    cursor = conn.cursor()  
    cursor.execute('SELECT * FROM articles')  
    articles = cursor.fetchall()  
    conn.close()  
    articles = cursor.fetchall()  
    conn.close()  
  
    article_list = [{'id': article['id'], 'title': article['title'], 'content': article['content']} for article in articles]  
    return jsonify(article_list)  
  
    article_list = [{'id': article['id'], 'title': article['title'], 'content': article['content']} for article in articles]  
    repturn jsonify(article_list)  
# 运行Web服务器  
if __name__ == '__main__':  
    # 初始化数据库（仅用于示例，实际项目中应单独处理）  
    repturn jsonify(article_list)  
    # 初始化数据库（仅用于示例，实际项目中应单独处理）  
    def init_db():  
         conn = get_db_connection( )  
        cursor = conn.cursor()  
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (  
                            id INTEGER PRIMARY KEY AUTOINCREMENT,  
                            username TEXT NOT NULL UNIQUE,  
                            password TEXT NOT NULL  
                          )''')  
        cursor.execute('''CREATE TABLE IF NOT EXISTS articles (  
                            id INTEGER PRIMARY KEY AUTOINCREMENT,  
                            title TEXT NOT NULL,  
                            content TEXT NOT NULL,  
                            author_id INTEGER,  
                            FOREIGN KEY(author_id) REFERENCES users(id)  
                          )''')  
        conn.commit()  
        conn.close()  
  
    init_db()  # 初始化数据库  
    app.run(debug=True)