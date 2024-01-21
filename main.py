from django.db import connection, models
from django.db.models.expressions import RawSQL
from flask import Flask, request
app = Flask(__name__)

class User(models.Model):
    pass

# @app.route("/users/<username>")
# def show_user(username):
#     with connection.cursor() as cursor:
#         # GOOD -- Using parameters
#         cursor.execute("SELECT * FROM users WHERE username = %s", username)
#         User.objects.raw("SELECT * FROM users WHERE username = %s", (username,))

#         # BAD -- Using string formatting
#         cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)

#         # BAD -- other ways of executing raw SQL code with string interpolation
#         User.objects.annotate(RawSQL("insert into names_file ('name') values ('%s')" % username))
#         User.objects.raw("insert into names_file ('name') values ('%s')" % username)
#         User.objects.extra("insert into names_file ('name') values ('%s')" % username)

#         # BAD (but currently no custom query to find this)
#         #
#         # It is exposed to SQL injection (https://docs.djangoproject.com/en/2.2/ref/models/querysets/#extra)
#         # For example, using name = "; DROP ALL TABLES -- "
#         # will result in SQL: SELECT * FROM name WHERE name = ''; DROP ALL TABLES -- ''
#         #
#         # This shouldn't be very widespread, since using a normal string will result in invalid SQL
#         # Using name = "example", will result in SQL: SELECT * FROM name WHERE name = ''example''
#         # which in MySQL will give a syntax error
#         #
#         # When testing this out locally, none of the queries worked against SQLite3, but I could use
#         # the SQL injection against MySQL.
#         User.objects.raw("SELECT * FROM users WHERE username = '%s'", (username,))

import builtins
def imagemath_eval_vulnerable(expression, _dict={}, **kw):
    """
    Evaluates an image expression.

    :param expression: A string containing a Python-style expression.
    :param options: Values to add to the evaluation context.  You
                    can either use a dictionary, or one or more keyword
                    arguments.
    :return: The evaluated expression. This is usually an image object, but can
             also be an integer, a floating point value, or a pixel tuple,
             depending on the expression.
    """

    # build execution namespace
    args = ops.copy()
    args.update(_dict)
    args.update(kw)
    for k, v in list(args.items()):
        if hasattr(v, "im"):
            pass

    out = builtins.eval(expression, args)

def imagemath_eval_fixed(expression: str, _dict: dict[str, Any] = {}, **kw: Any) -> Any:
    """
    Evaluates an image expression.

    :param expression: A string containing a Python-style expression.
    :param options: Values to add to the evaluation context.  You
                    can either use a dictionary, or one or more keyword
                    arguments.
    :return: The evaluated expression. This is usually an image object, but can
             also be an integer, a floating point value, or a pixel tuple,
             depending on the expression.
    """

    # build execution namespace
    args: dict[str, Any] = ops.copy()
    for k in list(_dict.keys()) + list(kw.keys()):
        if "__" in k or hasattr(builtins, k):
            msg = f"'{k}' not allowed"
            raise ValueError(msg)

    args.update(_dict)
    args.update(kw)
    for k, v in args.items():
        if hasattr(v, "im"):
            args[k] = _Operand(v)

    compiled_code = compile(expression, "<string>", "eval")

    def scan(code: CodeType) -> None:
        for const in code.co_consts:
            if type(const) is type(compiled_code):
                scan(const)

        for name in code.co_names:
            if name not in args and name != "abs":
                msg = f"'{name}' not allowed"
                raise ValueError(msg)

    scan(compiled_code)
    out = builtins.eval(expression, {"__builtins": {"abs": abs}}, args)
    

from PIL import Image, ImageMath
@app.route("/files/<expression>")
def analyze_file(expression):
  with Image.open("image1.jpg") as im1:
    with Image.open("image2.jpg") as im2:
        out = ImageMath.eval(expression, a=im1, b=im2)
        out2 = imagemath_eval_vulnerable(expression, a=im1, b=im2)
        out2 = imagemath_eval_fixed(expression, a=im1, b=im2)
        out.save("result.png")
  
