from flask import *
app = Flask(__name__)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def send_exp(path):
    return render_template('exp.html')


app.run(host="0.0.0.0", port=8000)
