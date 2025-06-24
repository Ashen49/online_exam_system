from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///exam_system.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'png', 'jpg', 'jpeg'}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    is_admin = db.Column(db.Boolean, default=False)

class Paper(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    filename = db.Column(db.String(150))

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    paper_id = db.Column(db.Integer, db.ForeignKey('paper.id'))
    filename = db.Column(db.String(150))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password, method='sha256'))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful, please login')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        papers = Paper.query.all()
        return render_template('admin_dashboard.html', papers=papers)
    else:
        papers = Paper.query.all()
        return render_template('student_dashboard.html', papers=papers)

@app.route('/upload_paper', methods=['GET', 'POST'])
@login_required
def upload_paper():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        title = request.form.get('title')
        file = request.files['file']
        if file and allowed_file(file.filename) and file.filename.endswith('.pdf'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            new_paper = Paper(title=title, filename=filename)
            db.session.add(new_paper)
            db.session.commit()
            flash('Paper uploaded successfully')
            return redirect(url_for('dashboard'))
        else:
            flash('Please upload a valid PDF file')
            return redirect(url_for('upload_paper'))
    return render_template('upload_paper.html')

@app.route('/paper/<int:paper_id>', methods=['GET', 'POST'])
@login_required
def paper_detail(paper_id):
    paper = Paper.query.get_or_404(paper_id)
    if request.method == 'POST':
        files = request.files.getlist('answers')
        for file in files:
            if file and allowed_file(file.filename) and file.filename != '' and not file.filename.endswith('.pdf'):
                filename = secure_filename(f"{current_user.id}_{paper.id}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                answer = Answer(user_id=current_user.id, paper_id=paper.id, filename=filename)
                db.session.add(answer)
        db.session.commit()
        flash('Answers uploaded successfully')
        return redirect(url_for('dashboard'))
    return render_template('paper_detail.html', paper=paper)

@app.route('/answers/<int:paper_id>')
@login_required
def view_answers(paper_id):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    answers = Answer.query.filter_by(paper_id=paper_id).all()
    return render_template('view_answers.html', answers=answers)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
