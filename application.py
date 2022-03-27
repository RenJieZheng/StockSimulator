import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

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
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    get_cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    cash = get_cash[0]["cash"]
    total_cash = cash
    table_data = list()
    rows = db.execute("SELECT DISTINCT symbol FROM transactions WHERE id=:user_id", user_id=session["user_id"])
    for row in rows:
        stock = lookup(row["symbol"])
        get_shares = db.execute("SELECT SUM(shares) FROM transactions WHERE symbol=:symbol AND id=:user_id", symbol=row["symbol"], user_id=session["user_id"])
        shares = get_shares[0]['SUM(shares)']
        if not shares == 0:
            table_data.append(
                [
                    row["symbol"].upper(),
                    stock["name"],
                    shares,
                    usd(stock["price"]),
                    usd(float(shares) * stock["price"])
                ]
            )
            total_cash = total_cash + (float(shares) * stock["price"])
    return render_template("index.html", table_data=table_data, cash=usd(cash), total_cash=usd(total_cash))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST
    if request.method == "POST":
        # Ensure form was submitted correctly
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("missing symbol", 400)
        if not shares:
            return apology("missing shares", 400)
        shares = int(shares)
        if shares < 1:
            return apology("invalid value for shares", 400)

        # Lookup the stock and calculate cash
        symbol = symbol.upper()
        stock = lookup(symbol)
        if stock == None:
            return apology("invalid symbol", 400)
        get_cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        cash = get_cash[0]["cash"]
        price = float(shares) * stock["price"]
        new_cash = cash - price
        if new_cash < 0:
            return apology("cannot afford", 400)

        # Update database
        db.execute("UPDATE users SET cash=:cash WHERE id=:user_id", cash=new_cash, user_id=session["user_id"])
        db.execute("INSERT INTO transactions (id, symbol, shares, price, time) VALUES (:user_id, :symbol, :shares, :price, :time)",
        user_id=session["user_id"], symbol=symbol, shares=shares, price=stock["price"], time=datetime.today())
        flash("Bought!")
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    table_data = db.execute("SELECT symbol, shares, price, time FROM transactions WHERE id=:user_id ORDER BY time DESC", user_id=session["user_id"])
    return render_template("history.html", table_data=table_data)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

     # User reached route via POST
    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        if stock is None:
            return apology("invalid symbol", 400)
        return render_template("quoted.html", name=stock["name"], symbol=stock["symbol"], price=stock["price"])

    # User reached route via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST
    if request.method == "POST":
        # Ensure form was submitted correctly
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)
        elif not confirmation:
            return apology("must confirm your password", 403)
        elif not password == confirmation:
            return apology("passwords do not match", 403)

        # Inserts new user into database
        password_hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :password_hash)", username=username, password_hash=password_hash)

        # Log user in
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if not symbol:
            return apology("missing symbol", 400)
        if not shares:
            return apology("missing shares", 400)
        if not shares > 0:
            return apology("shares much be positive", 400)

        stock = lookup(symbol)
        get_current_shares = db.execute("SELECT SUM(shares) FROM transactions WHERE symbol=:symbol AND id=:user_id", symbol=symbol, user_id=session["user_id"])
        current_shares = get_current_shares[0]["SUM(shares)"]
        if shares > current_shares:
            return apology("too many shares", 400)

        get_cash = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session["user_id"])
        cash = get_cash[0]["cash"]
        cash = cash + (float(request.form.get("shares")) * stock["price"])

        db.execute("INSERT INTO transactions (id, symbol, shares, price, time)  VALUES (:user_id, :symbol, :shares, :price, :time)", user_id=session["user_id"],
        symbol=symbol, shares=shares*-1, price=stock["price"], time=datetime.today())
        db.execute("UPDATE users SET cash=:cash WHERE id=:user_id", cash=cash, user_id=session["user_id"])

        return redirect("/")

    # User reached route via GET
    else:
        rows = db.execute("SELECT DISTINCT symbol FROM transactions WHERE id=:user_id", user_id=session["user_id"])
        stocks = list()
        for row in rows:
            symbol = row["symbol"]
            get_shares = db.execute("SELECT SUM(shares) FROM transactions WHERE symbol=:symbol AND id=:user_id", symbol=row["symbol"], user_id=session["user_id"])
            shares = get_shares[0]['SUM(shares)']
            if not shares == 0:
                stocks.append(symbol)
        return render_template("sell.html", stocks=stocks)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change users password"""

    # User reached route via POST
    if request.method == "POST":
        # Check if user has filled out the form correctly
        current = request.form.get("current")
        new = request.form.get("new")
        if not current:
            return apology("Please enter your current password", 403)
        if not new:
            return apology("Please enter your new password", 403)

        # Check if the current password was entered correctly
        rows = db.execute("SELECT * FROM users WHERE id = :id",id=session["user_id"])
        if not check_password_hash(rows[0]["hash"], current):
            return apology("invalid password", 403)

        # Check if the new password is different than the current one
        if current == new:
            return apology("The new password is identical to the old one", 403)

        # Update the users password
        new_password_hash = generate_password_hash(new, method='pbkdf2:sha256', salt_length=8)
        db.execute("UPDATE users SET hash=:hash WHERE id=:user_id", hash=new_password_hash, user_id=session["user_id"])
        flash("Password Updated")
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("changepassword.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)