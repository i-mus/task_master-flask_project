

from flask import Flask, flash, render_template, request,redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager,logout_user,login_user,login_required
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField,SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import sqlite3 
  
# Connecting to sqlite 
conn = sqlite3.connect('gfg1.db') 
  
# Creating a cursor object using  
# the cursor() method 
cursor = conn.cursor()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable =False)
    date_created = db.Column(db.DateTime, default =datetime.utcnow )
    
    
    def __repr__(self):
        return '<Task %r>' % self.id

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    name = db.Column(db.String(200))
    password = db.Column(db.String(200),nullable=False)
    
    def __init__(self, email, name, password):
        self.email = email
        self.name = name
        self.password = password


@app.route('/', methods= ['GET', 'POST'])
def home():
    # if 'username' in session:
    #     return render_template('home.html',username= session['username'])
    # else:
    #     return render_template('home.html')
    if request.method == "POST":
        task = request.form['task']
        new_task = Todo(content=task)
        
        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/')
        except:
            return('There was an issue adding your task')
    else:
        tasks = Todo.query.order_by(Todo.date_created).all()
        return render_template("home.html", tasks=tasks)
    
@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/')
    except:
        return 'There is a error in deleting your task'


@app.route('/update/<int:id>', methods= ['GET', 'POST'])
def update(id):
    task = Todo.query.get_or_404(id)
    if request.method == 'POST':
        task.content = request.form['task']
        try:
            db.session.commit()
            return redirect('/')
        except:
            return 'There is error in updating the task'
    else:
        return render_template('update.html', task=task)


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        msg = None
        user_name = None
        email = request.form['email']
        password = request.form['password']
        user= User.query.filter_by(email=email).first()
        if user:
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                
                return redirect('/')
            else:
                return render_template('login.html', msg="password is wrong")
        else:
            return render_template('login.html', msg="User does Not exist")
    return render_template('login.html')


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        cpassword = request.form['cpassword']
        
        if User.query.filter_by(User.email==email).count() > 0:
            return render_template('register.html', msg="Email already exist") 
        
        if password == cpassword:
            msg = None
            hashed_pass = bcrypt.generate_password_hash(password)
            new_user = User(email, name, hashed_pass)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            return render_template('register.html', msg="password not matching")
            
    return render_template('register.html')

@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You were logged out.", "success")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)