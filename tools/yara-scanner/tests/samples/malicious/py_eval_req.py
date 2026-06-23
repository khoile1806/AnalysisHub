from flask import request

def run():
    return eval(request.args.get("payload"))
