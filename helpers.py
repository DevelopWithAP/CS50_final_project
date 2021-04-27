# All functions in this section are courtesy of CS50's pset8/finance except validate_password()

import os
import requests
import re

from flask import redirect, render_template, request, session, flash
from functools import wraps

# apology template
def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code

# ensures user is logeed in to perform
def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# function called to validate password
def validate_password(first_password, second_password):
    hasDigit = re.search(r"[0-9]", first_password)
    if not first_password:
        flash("Must provide password", "warning")
    elif len(first_password) < 8:
        flash("Password must be at least 8 characters long", "warning")
    elif first_password.islower() == True:
        flash("Password must contain at least one upper case character", "warning")
    elif hasDigit is None:
        flash("Password must contain at least one number", "warning")
    elif not second_password:
        flash("Must confirm password", "warning")
    elif not first_password == second_password:
        flash("Passwords must match", "warning")

    if first_password and len(first_password) > 8 and first_password.islower() == False and hasDigit != None and first_password == second_password:
        return True
    return False