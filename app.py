import sqlite3
import bcrypt
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )

    user = cursor.fetchone()
    conn.close()

    if user is None:
        return render_template("index.html",error="User not found")

    hashed_password = user[0]

    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode("utf-8")

    if bcrypt.checkpw(password.encode("utf-8"), hashed_password):
        return f"{username} logged in successfully!"

    return render_template("index.html",error="Wrong password. Please try again.")

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    username = request.form['username']
    password = request.form['password']

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()

    except sqlite3.IntegrityError:
        return render_template("register.html",error="Username already exists. Please choose a different username.")
    
    finally:
        conn.close()

    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True) 

