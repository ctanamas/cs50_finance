import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

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
    # update price
    final_total = 0.0
    prices = []

    portfolio = db.execute("SELECT symbol, name, owned_shares, price FROM stocks WHERE user == :user", user=session["user_id"])
    for i in range(0, len(portfolio)):
        symbol = portfolio[i]['symbol']

        price = lookup(symbol)['price']
        prices.append(price)

        db.execute("UPDATE stocks SET price = :price WHERE symbol == :symbol AND user == :user",
                   price=price, symbol=symbol, user=session["user_id"])

    portfolio = db.execute("SELECT symbol, name, owned_shares, price FROM stocks WHERE user == :user", user=session["user_id"])

    # formating price row and adding total and cash row to the dict we pass in
    for i in range(0, len(portfolio)):
        portfolio[i]['total'] = prices[i] * portfolio[i]['owned_shares']
        final_total += portfolio[i]['total']
        portfolio[i]['total'] = usd(portfolio[i]['total'])
        portfolio[i]['price'] = usd(portfolio[i]['price'])

    cash = db.execute("SELECT cash FROM users WHERE id == :user", user=session["user_id"])[0]['cash']
    final_total += cash

    final_total = usd(final_total)
    cash = usd(cash)

    return render_template("index.html", portfolio=portfolio, final_total=final_total, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")
    else:
        shares = request.form.get("shares")
        symbol = request.form.get("symbol")
        result = lookup(symbol)

        try:
            shares = int(shares)
            if shares < 1:  # if not a positive int print message and ask for input again
                return apology("The number of shares must be a positive integer")
        except ValueError:
            return apology("The number of shares must be a positive integer")

        if not result:
            return apology("invalid stock symbol", 403)

        symbol = symbol.upper()

        total_cost = result['price'] * shares
        cash = db.execute("SELECT cash FROM users WHERE id == :user", user=session["user_id"])
        if (total_cost) > float(cash[0]['cash']):
            return apology("Not enough cash!", 403)
        else:
            # add a row to the history
            db.execute("INSERT INTO history (user, number_of_shares, value, symbol, date) VALUES (:user, :shares, :value, :symbol, CURRENT_TIMESTAMP)",
                       user=session["user_id"], shares=shares, value=result['price'], symbol=symbol)

            db.execute("UPDATE users SET cash= cash - :price WHERE id == :user", price=total_cost, user=session["user_id"])

            # add to stocks if you are buying more of something you only need to increment owned_shares and update price
            if len(db.execute("SELECT * FROM stocks WHERE user = :user AND symbol = :symbol", user=session["user_id"], symbol=symbol)) == 0:
                db.execute("INSERT INTO stocks (user, symbol, name, owned_shares, price) VALUES (:user, :symbol, :name, :shares, :value)",
                           user=session["user_id"], symbol=symbol, name=result['name'], shares=shares, value=result['price'])
            else:
                db.execute("UPDATE stocks SET owned_shares = owned_shares + :shares WHERE user == :user AND symbol == :symbol",
                           shares=shares, user=session["user_id"], symbol=symbol)
            return redirect("/")


@app.route("/history")
@login_required
def history():

    history = db.execute("SELECT symbol, number_of_shares, value, date FROM history WHERE user == :user", user=session["user_id"])

    # formating price row
    for i in range(len(history)):
        history[i]['value'] = usd(history[i]['value'])

    return render_template("history.html", history=history)


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
    if request.method == "GET":
        return render_template("quote.html")
    else:
        result = lookup(request.form.get("symbol"))
        if not result:
            return apology("invalid symbol", 403)
        else:
            return render_template("quoted.html", name=result["name"], price=usd(result["price"]), symbol=result["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    else:

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure username is not taken
        if len(db.execute("SELECT username FROM users WHERE username=:username", username=username)) != 0:
            return apology("username taken", 403)

        # Ensure password was submitted and confirmed
        elif not password or not confirmation:
            return apology("Please fill both password fields", 403)

        elif password != confirmation:
            return apology("the password fields do not match", 403)

        elif not(any(char.isdigit() for char in password) and any(char.isalpha() for char in password) and len(password) >= 6):
            return apology("Please ensure your password contains both letters and numbers, with a minimum length of 6 characters")

        else:
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
                       username=username, password=generate_password_hash(password))
            return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":

        result = db.execute("SELECT symbol, owned_shares FROM stocks WHERE user=:user", user=session['user_id'])
        stocks = {}

        for i in range(len(result)):
            stocks[result[i]['symbol']] = result[i]['owned_shares']

        return render_template("sell.html", stocks=stocks, test="test")

    else:
        shares = request.form.get("shares")
        symbol = request.form.get("symbol")
        owned_shares = db.execute("SELECT owned_shares FROM stocks WHERE user=:user AND symbol=:symbol",
                                  user=session['user_id'], symbol=symbol)

        if symbol == None:
            return apology("Please select a stock symbol")

        symbol = symbol.upper()

        owned_shares = owned_shares[0]['owned_shares']
        result = lookup(symbol)

        if owned_shares == 0:
            return apology("Sorry, you do not own any shares of this symbol")

        try:
            shares = int(shares)
            if shares < 1:  # if not a positive int print message and ask for input again
                return apology("The number of shares to sell must be a positive integer")
        except ValueError:
            return apology("The number of shares to sell must be a positive integer")

        if shares > owned_shares:
            return apology("You cannot sell more stocks than you own", 403)

        if not result:
            return apology("invalid stock symbol", 403)

        # update cash owned
        cash_gained = result['price'] * shares
        db.execute("UPDATE users SET cash = cash + :gained WHERE id == :user", gained=cash_gained, user=session["user_id"])

        # add a row to the history
        db.execute("INSERT INTO history (user, number_of_shares, value, symbol, date) VALUES (:user, :shares, :value, :symbol, CURRENT_TIMESTAMP)",
                   user=session["user_id"], shares=shares * -1, value=result['price'], symbol=symbol)

        if owned_shares - shares == 0:
            # delete row if total shares you own of that stock == 0:
            db.execute("DELETE FROM stocks WHERE user=:user AND symbol=:symbol", user=session['user_id'], symbol=symbol)
        else:
            # update owned_shares
            db.execute("UPDATE stocks SET owned_shares=owned_shares - :shares WHERE user == :user AND symbol == :symbol",
                       shares=shares, user=session["user_id"], symbol=symbol)

        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
