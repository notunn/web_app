from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from datetime import datetime
from sqlalchemy import create_engine, text
app = Flask(__name__)

# Cs50
# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
engine = create_engine('sqlite:///database.db')

# return dictionary of query
def query_db(query, params):
    with engine.connect() as connection:
        
        result = connection.execute(text(query), params).fetchall()
        results = []
        
        for row in result:
            for column, value in row.items():
                results.append({column: value})
        
    return results


# Cs50
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    
    if request.method == "POST":
        name = request.form.get("name")
        password = request.form.get("password")
        if not name or not password:
            print("Missing username or password")
            return render_template("error.html", message="Please enter username and password")
        
        rows = query_db("SELECT * FROM users WHERE name = :name", {"name": name})
        
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):          
            return render_template("error.html", message="Invalid username or password")
        
        session.clear()
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    
    else:
        print("GET request received")
        return render_template("login.html")
    
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
        if not name or not password or not confirmation:
            return render_template("error.html", message="Please enter username and password")
        
        if len(name) <= 2 or len(password) <=2:
            return render_template("error.html", message="Username and password must be at least 3 characters")
        
        if password != confirmation:
            return render_template("error.html", message="Passwords do not match")
        
        if name in query_db("SELECT name FROM users", {}):
            return render_template("error.html", message="Username already exists")
        
        hash = generate_password_hash(password)
        with engine.connect() as connection:
            connection.execute(text("INSERT INTO users (name, hash) VALUES (:name, :hash)"), {"name": name, "hash": hash})
            connection.commit()
        
        return redirect("/login")
    
    else:
        return render_template("register.html")