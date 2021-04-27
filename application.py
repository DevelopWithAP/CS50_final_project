import os
import re

from cs50 import SQL
from tempfile import mkdtemp
from flask import Flask, render_template, redirect, request, session, flash
from flask_session import Session

from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash, safe_str_cmp

from helpers import validate_password, apology, login_required

app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses are not cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use file system
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# configure CS50 library to use SQLite DB
db = SQL("sqlite:///log.db")


# default route
@app.route("/")
@login_required
def index():
    rows = db.execute("""
            SELECT *
            FROM users
            WHERE id = :user_id
                    """, user_id = session["user_id"])
    username = rows[0]["username"]
    position = rows[0]["position"]

    return render_template("index.html", username = username, position = position)

# Register user
@app.route("/register", methods = ["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        position = request.form["position"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not username:
            flash("Must provide name", "warning")
            return redirect("/register")

        if not position:
            flash("Must provide role", "warning")
            return redirect("/register")


        # Perform password checks
        if validate_password(password, confirm_password) == False:
            return redirect("/register")
        else:

            # hash user password
            hash = generate_password_hash(password, method = "pbkdf2:sha256", salt_length = 8)

            # check new user not already registered
            rows = db.execute("SELECT * FROM users")
            db_usernames = []
            for item in rows:
                db_usernames.append(item["username"])
            if username in db_usernames:
                flash("Employee name already exists. Try logging in", "warning")
                return redirect ("/register")

            # insert user in log.db
            primary_key = db.execute("INSERT INTO users (username, position, hash) VALUES (:username, :position, :hash)", username = username, position = position, hash = hash)
            if primary_key is None:
                flash("Registration error")
                return redirect("/register")
            session["user_id"] = primary_key

            flash("Employee added!", "success")
            return redirect("/")


@app.route("/login", methods = ["GET", "POST"])
def login():
    # clear session
    session.clear()

    if request.method == "GET":
        return render_template("login.html")
    else:
        username = request.form["username"]
        password = request.form["password"]

        # if not username or not password:
        #     flash("Missing username and/or password","danger")
        #     return redirect("/login")
        if not username or not password:
            return apology("Missing username and/or password", 400)


        # pull username from database
        rows = db.execute("""
                SELECT *
                FROM users
                WHERE username = :username
                        """, username = username)
        # check username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("Invalid credentials")

        # start user session
        session["user_id"] = rows[0]["id"]

        flash("You were successfully logged in", "success")
        # redirest user to homepage
        return redirect("/")

# log user out
@app.route("/logout")
def logout():
    # clear any existing sessions
    session.clear()
    # redirect user to default route
    return redirect("/")

# Manage account
@app.route("/account_settings")
@login_required
def manage_account():
    rows = db.execute("SELECT * FROM users WHERE id = :id", id = session["user_id"])
    username = rows[0]["username"]

    return render_template("manage_account.html", username = username)


# manage username
@app.route("/manage_username", methods = ["GET", "POST"])
@login_required
def manage_username():
    if request.method == "GET":
        return render_template("manage_username.html")
    else:
        username = request.form["username"]
        new_username = request.form["new_username"]
        confirm_new_username = request.form["confirm_new_username"]

        if not username or not new_username:
            flash("Missing fields", "warning")
            return redirect("/manage_username")
        if new_username != confirm_new_username:
            flash("Usernames did not match", "warning")
            return redirect("/manage_username")

        rows = db.execute("""
                    SELECT *
                    FROM users
                    WHERE id = :user_id
                        """, user_id = session["user_id"])
        user = rows[0]["username"]

        if new_username == user:
            flash("Username already in use.", "warning")
            return redirect
        else:
            rows = db.execute("""
                    UPDATE users
                    SET username = :new_username
                    WHERE id = :user_id
                            """, new_username = new_username, user_id = session["user_id"])
            flash("Username successully updated", "success")
            return redirect("/")

# manage password
@app.route("/manage_password", methods=["GET", "POST"])
@login_required
def manage_password():
    if request.method == "GET":
        return render_template("manage_password.html")
    else:
        password = request.form["password"]
        new_password = request.form["new_password"]
        confirm_new_password = request.form["confirm_new_password"]
        new_hash = generate_password_hash(new_password, method = "pbkdf2:sha256", salt_length = 8)

        if validate_password(new_password, confirm_new_password) == False:
            return redirect("/manage_password")
        else:
            rows = db.execute("""
                    SELECT *
                    FROM users
                    WHERE id = :user_id
                            """, user_id = session["user_id"])
            current_hash = rows[0]["hash"]
            if safe_str_cmp(current_hash, new_hash) == True:
                flash("Password in use", "warning")
                return redirect("/manage_password")
            else:
                rows = db.execute("""
                        UPDATE users
                        SET hash = :new_hash
                        WHERE id = :user_id
                                """, new_hash = new_hash, user_id = session["user_id"])
                flash("Password successfully updated", "success")
                return redirect

# forgot password
@app.route("/forgot_password", methods = ["GET", "POST"])
def forgot_password():
    if request.method =="GET":
        return render_template("forgot_password.html")
    else:
        username = request.form["username"]

        rows = db.execute("SELECT * FROM users")
        db_usernames = []
        for item in rows:
            db_usernames.append(item.get("username"))
        if not username:
            flash("Missing employee name", "warning")
            return redirect("/forgot_password")
        if username not in db_usernames:
            flash("Unable to retrieve name", "danger")
            return redirect("/forgot_password")
        else:
            return render_template("reset_password.html")


@app.route("/reset_password", methods = ["POST"])
def reset_password():
    username = request.form["username"]
    password = request.form["password"]
    confirm_password = request.form["confirm_password"]

    if validate_password(password, confirm_password) == False:
        return redirect("/forgot_password")
    else:

        hash = generate_password_hash(password, method = "pbkdf2:sha256", salt_length = 8)
        rows = db.execute("""
                    UPDATE users
                    SET hash = :hash
                    WHERE username = :username
                        """, hash = hash, username = username)
        return apology("Success! You can log in using your new credentials", 400)

# Create new log
@app.route("/new_log")
@login_required
def create_log():
        return render_template("coffee_log.html")

# Log Espresso data
@app.route("/log_espresso", methods = ["GET", "POST"])
@login_required
def log_espresso():
    if request.method == "GET":
        return render_template("espresso_log.html")
    else:
        acidity = request.form["acidity"]
        bitterness = request.form.get("bitterness")
        sweetness = request.form["sweetness"]
        name = request.form["name"]
        batch_number = request.form["batch_number"]
        roast_date = request.form.get("roast_date")
        recipe = request.form["recipe"]
        time_frame = request.form["time_frame"]
        type = request.form["type"]
        tasting_notes = request.form["tasting_notes"]
        body = request.form["body"]
        aftertaste = request.form.get("aftertaste")
        balance = request.form["balance"]
        notes = request.form["notes"]

        rows = db.execute("""
                INSERT INTO espresso_log (user_id, name, batch_number, recipe, roast_date, time_frame, acidity, sweetness, bitterness, tasting_notes, body, aftertaste, balance, notes, type)
                VALUES(:user_id, :name, :batch_number, :recipe, :roast_date, :time_frame, :acidity, :sweetness, :bitterness, :tasting_notes, :body, :aftertaste, :balance, :notes,:type)
                """,
                user_id = session["user_id"], name = name, batch_number = batch_number, roast_date = roast_date, recipe = recipe, time_frame = time_frame, acidity = acidity, sweetness = sweetness, bitterness = bitterness, tasting_notes = tasting_notes, body = body, aftertaste = aftertaste, balance = balance, notes = notes, type = type)
    flash("Log added successfully!", "success")
    return redirect("/new_log")

@app.route("/log_filter", methods=["GET", "POST"])
@login_required
def log_filter():
    if request.method == "GET":
        return render_template("filter_log.html")
    else:

        # 3temp
        T_name = request.form["T_name"]
        T_batch_number = request.form["T_batch_number"]
        T_roast_date = request.form["T_roast_date"]
        T_grind_size = request.form["T_grind_size"]
        T_dose = request.form["T_dose"]
        T_ratio = request.form["T_ratio"]
        step_1 = request.form["step_1"]
        step_2 = request.form["step_2"]
        step_3 = request.form["step_3"]
        T_tasting_notes = request.form["T_tasting_notes"]
        T_aroma = request.form["T_aroma"]
        T_acidity = request.form["T_acidity"]
        T_sweetness = request.form["T_sweetness"]
        T_bitterness = request.form["T_bitterness"]
        T_body = request.form["T_body"]

        rows = db.execute("""
        INSERT INTO filter_log (user_id, T_name, T_batch_number, T_roast_date, T_grind_size,
                                T_dose, T_ratio, step_1, step_2, step_3, T_tasting_notes, T_aroma,
                                T_acidity, T_sweetness, T_bitterness, T_body)
        VALUES (:user_id, :T_name, :T_batch_number, :T_roast_date,
                                :T_grind_size, :T_dose, :T_ratio, :step_1, :step_2,
                                :step_3, :T_tasting_notes, :T_aroma, :T_acidity,
                                :T_sweetness, :T_bitterness, :T_body)
        """,user_id = session["user_id"], T_name = T_name, T_batch_number = T_batch_number, T_roast_date = T_roast_date,
            T_grind_size = T_grind_size, T_dose = T_dose, T_ratio = T_ratio, step_1 = step_1, step_2 = step_2, step_3 = step_3, T_tasting_notes = T_tasting_notes,
            T_aroma = T_aroma, T_acidity = T_acidity, T_sweetness = T_sweetness, T_bitterness = T_bitterness, T_body = T_body)
        flash("Log added successfully!", "success")
        return redirect("/new_log")

# log v60
@app.route("/log_v60", methods=["GET", "POST"])
def log_v60():
    if request.method == "GET":
        return render_template("v60_log.html")
    else:
        v60_name = request.form["v60_name"]
        v60_batch_number = request.form["v60_batch_number"]
        v60_roast_date = request.form["v60_roast_date"]
        v60_grind_size = request.form["v60_grind_size"]
        v60_ratio = request.form["v60_ratio"]
        v60_recipe = request.form["v60_recipe"]
        v60_tasting_notes = request.form["v60_tasting_notes"]

        rows = db.execute("""
                    INSERT INTO v60_log (user_id, v60_name, v60_batch_number, v60_roast_date,
                                        v60_grind_size, v60_ratio, v60_recipe, v60_tasting_notes)
                    VALUES(:user_id, :v60_name, :v60_batch_number, :v60_roast_date, :v60_grind_size,
                            :v60_ratio, :v60_recipe, :v60_tasting_notes)
                        """, user_id = session["user_id"], v60_name = v60_name, v60_batch_number = v60_batch_number,
                             v60_roast_date = v60_roast_date, v60_grind_size = v60_grind_size, v60_ratio = v60_ratio,
                             v60_recipe = v60_recipe, v60_tasting_notes = v60_tasting_notes)
        flash("Log added successfully!", "success")
        return redirect("/new_log")


# history
@app.route("/history")
@login_required
def history():
    rows = db.execute("SELECT * FROM espresso_log")

    notes = []
    dates = []
    recipes = []
    type = []
    for row in reversed(rows):
        dates.append(row["date"])
        recipes.append(row["recipe"])
        notes.append(row["tasting_notes"])
        type.append(row["type"])

    last_rec = dates[0]
    second2last_rec = dates[1]

    last_type = type[0]
    second2last_type = type[1]

    last_recipe = recipes[0]
    second_to_last_recipe = recipes[1]

    last_notes = notes[0]
    second_to_last_notes = notes[1]

    rows = db.execute("SELECT * FROM filter_log")
    dates = []
    names = []
    batches = []
    roasted = []
    grind_sizes = []
    doses = []
    ratios = []

    for row in reversed(rows):
        dates.append(row["date"])
        names.append(row["T_name"])
        batches.append(row["T_batch_number"])
        roasted.append(row["T_roast_date"])
        grind_sizes.append(row["T_grind_size"])
        doses.append(row["T_dose"])
        ratios.append(row["T_ratio"])

    last_filter = names[0]
    sec_to_last_filter = names[1]

    last_date = dates[0]
    sec_to_last_date = dates[1]

    last_batch_no = batches[0]
    sec_to_last_batch_no = batches[1]

    last_roasted = roasted[0]
    sec_to_last_roasted = roasted[1]

    last_grind_size = grind_sizes[0]
    sec_to_grind_size = grind_sizes[1]

    last_dose = doses[0]
    sec_to_dose = doses[1]

    last_ratio = ratios[0]
    sec_to_ratio = ratios[1]

    rows = db.execute("SELECT * FROM v60_log")
    v60_names = []
    v60_dates = []
    v60_batch_nos = []
    v60_roast_dates = []
    v60_grind_sizes = []
    v60_ratios = []
    v60_recipes = []
    v60_notes = []

    for row in reversed(rows):
        v60_names.append(row["v60_name"])
        v60_dates.append(row["date"])
        v60_batch_nos.append(row["v60_batch_number"])
        v60_roast_dates.append(row["v60_roast_date"])
        v60_grind_sizes.append(row["v60_grind_size"])
        v60_ratios.append(row["v60_ratio"])
        v60_recipes.append(row["v60_recipe"])
        v60_notes.append(row["v60_tasting_notes"])

    last_v60 = v60_names[0]
    sec_to_last_v60 = v60_names[1]

    last_v60_date = v60_dates[0]
    sec_to_last_v60_date = v60_dates[1]

    last_v60_batch_no = v60_batch_nos[0]
    sec_to_last_v60_batch_no = v60_batch_nos[1]

    last_v60_roast_date = v60_roast_dates[0]
    sec_to_last_v60_roast_date = v60_roast_dates[1]

    last_v60_grind_size = v60_grind_sizes[0]
    sec_to_last_v60_grind_size = v60_grind_sizes[1]

    last_v60_ratio = v60_ratios[0]
    sec_to_last_v60_ratio = v60_ratios[1]

    last_v60_recipe = v60_recipes[0]
    sec_to_last_v60_recipe = v60_recipes[1]

    last_v60_notes = v60_notes[0]
    sec_to_last_v60_notes = v60_notes[1]


    return render_template("history.html", last_record = last_rec, second_to_last_record = second2last_rec,
                            last_type = last_type, second_to_last_type = second2last_type, last_recipe = last_recipe,
                            second_to_last_recipe = second_to_last_recipe, last_notes = last_notes, second_to_last_notes = second_to_last_notes,
                            last_filter = last_filter, sec_to_last_filter = sec_to_last_filter, last_date = last_date, sec_to_last_date = sec_to_last_date,
                            last_batch_no = last_batch_no, sec_to_last_batch_no = sec_to_last_batch_no, last_roasted = last_roasted,
                            sec_to_last_roasted = sec_to_last_roasted, last_grind_size = last_grind_size, sec_to_grind_size = sec_to_grind_size, last_dose = last_dose, sec_to_dose = sec_to_dose,
                            last_ratio = last_ratio, sec_to_ratio = sec_to_ratio,
                            last_v60 = last_v60, sec_to_last_v60 = sec_to_last_v60,
                            last_v60_date = last_v60_date, sec_to_last_v60_date = sec_to_last_v60_date,
                            last_v60_batch_no = last_v60_batch_no, sec_to_last_v60_batch_no = sec_to_last_v60_batch_no,
                            last_v60_roast_date = last_v60_roast_date, sec_to_last_v60_roast_date = sec_to_last_v60_roast_date,
                            last_v60_grind_size = last_v60_grind_size, sec_to_last_v60_grind_size = sec_to_last_v60_grind_size,
                            last_v60_ratio = last_v60_ratio, sec_to_last_v60_ratio = sec_to_last_v60_ratio,
                            last_v60_recipe = last_v60_recipe, sec_to_last_v60_recipe = sec_to_last_v60_recipe,
                            last_v60_notes = last_v60_notes, sec_to_last_v60_notes = sec_to_last_v60_notes)






