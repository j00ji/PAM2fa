from flask import Flask, jsonify

app = Flask(__name__)
valid_tokens = {}  # Dicionário para armazenar tokens válidos

@app.route('/auth/<token>', methods=['GET'])
def authenticate(token):
    # Quando o link é clicado, marque o token como validado
    valid_tokens[token] = True
    return jsonify({"status": "validated", "message": "Token has been validated!"}), 200

@app.route('/auth/<token>/status', methods=['GET'])
def check_status(token):
    # Checar se o token foi validado
    if valid_tokens.get(token, False):
        return jsonify({"status": "validated", "message": "Token is validated."}), 200
    else:
        return jsonify({"status": "pending", "message": "Token is not validated yet."}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
