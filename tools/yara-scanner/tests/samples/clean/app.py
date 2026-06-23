from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/echo")
def echo():
    payload = request.args.get("msg", "")
    return jsonify({"msg": payload[:200]})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
