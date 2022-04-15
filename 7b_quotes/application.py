import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd
from random import randint
# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///quote.db")
#db.execute("CREATE TABLE portfolio (stock TEXT, quantity INTEGER)")

#db.execute("CREATE TABLE transactions ( stock TEXT, quantity INTEGER, price INTEGER, date TEXT, FOREIGN KEY(user_id) REFERENCES users(id)")
# Make sure API key is set



@app.route("/")
@login_required
def index():
    results = db.execute("select * from quotes")
    if not results:
        return apology("There are currently no quotes")

    return render_template("index.html" , results = results)


@app.route("/addquote", methods=["GET", "POST"])
@login_required
def addquote():
    if request.method == "POST":
        quote = request.form.get("quote")
        person = request.form.get("person")
        date = datetime.now()
        type1 = request.form.get("type")
        ID = randint(-9999999999,9999999999)
        db.execute("insert into quotes (quote , date , person , type , id2 ) values ( ? , ? , ? , ? , ? )" , quote , date.strftime("%Y-%m-%d %H:%M:%S") , person , type1 , ID )
        return redirect('/')
    else:
        return render_template("addnote.html")




@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        hecd = rows[0]["id"]
        #print(hecd)
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("Must provide username.",400)

        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("Must provide pasword.",400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords don't match.",400)

        rt = db.execute("select username from users where username = :username",username = request.form.get("username"))

        if len(rt) > 0 :
            return apology("username has already been used",400)

        hashed_password = generate_password_hash(request.form.get("password"))
        usernames = request.form.get("username")
        result = db.execute("insert into users (username,hash) values(:username,:hash_)",username = request.form.get("username"),hash_ = hashed_password)

        userid = db.execute("select id from users where username = :username", username =request.form.get("username"))
        row = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        session["user_id"] = row[0]["id"]

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/voted", methods=["GET", "POST"])
@login_required
def vote():
    if request.method == "POST":
        id = request.form.get("symbol")
        results = db.execute("select * from quotes where id2 = ? " , id)
        if not results:
            return apology("Please Give A Valid Id")
        else:
            return ap("Thank You For Voting")

    else:
        return render_template("quote.html")


def errorhandler(e):
    """Handle error"""

    if not isinstance(e, HTTPException):
        e = InternalServerError()

    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
