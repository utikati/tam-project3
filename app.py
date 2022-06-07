##
# ===========================================
# =============== API TAM-Project3 ===============
# ===========================================
# =======2021/22 ==============================
# ===========================================
# ===========================================
##
# Authors:
# Jorge Martins

from flask import Flask, jsonify, request
import logging
import time
import psycopg2
import jwt
import json
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'it\xb5u\xc3\xaf\xc1Q\xb9\n\x92W\tB\xe4\xfe__\x87\x8c}\xe9\x1e\xb8\x0f'

NOT_FOUND_CODE = 400
OK_CODE = 200
SUCCESS_CODE = 201
BAD_REQUEST_CODE = 400
UNAUTHORIZED_CODE = 401
FORBIDDEN_CODE = 403
NOT_FOUND = 404
SERVER_ERROR = 500


@app.route('/', methods=["GET"])
def home():
    return "Bem vindo à API!"


##########################################################
# TOKEN INTERCEPTOR
##########################################################
def auth_user(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        content = request.get_json()
        if content is None or "token" not in content or not content["token"]:
            return jsonify({'Erro': 'Token está em falta!', 'Code': UNAUTHORIZED_CODE})

        try:
            token = content["token"]
            data = jwt.decode(token, app.config['SECRET_KEY'])

            decoded_token = jwt.decode(
                content['token'], app.config['SECRET_KEY'])
            if(decoded_token["expiration"] < str(datetime.utcnow())):
                return jsonify({"Erro": "O Token expirou!", "Code": NOT_FOUND_CODE})

        except Exception as e:
            return jsonify({'Erro': 'Token inválido', 'Code': FORBIDDEN_CODE})
        return func(*args, **kwargs)
    return decorated


##########################################################
# LOGIN
##########################################################
@app.route("/login", methods=['POST'])
def login():
    content = request.get_json()

    if "username" not in content or "password" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})

    get_user_info = """
                SELECT *
                FROM utilizadores
                WHERE user_name = %s AND user_password = crypt(%s, senha);
                """

    values = [content["username"], content["password"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
                token = jwt.encode({
                    'id': rows[0][0],
                    'administrador': rows[0][7],
                    'expiration': str(datetime.utcnow() + timedelta(hours=1))
                }, app.config['SECRET_KEY'])
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Utilizador não encontrado"})
    return {"Code": OK_CODE, 'Token': token.decode('utf-8')}

##########################################################
# Verificar Existência de Utilizador
##########################################################


def verificar_username(username) -> bool:
    content = request.get_json()

    get_user_info = """
                SELECT *
                FROM utilizadores
                WHERE user_name = %s;
                """

    values = [content[username]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return False
    return True

##########################################################
# REGISTO DE UTILIZADOR
##########################################################


@app.route("/registar_utilizador", methods=['POST'])
def registar_utilizador():
    content = request.get_json()

    if "username" not in content or "password" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})

    get_user_info = """
                INSERT INTO useron(user_name, user_password) 
                VALUES(%s, crypt(%s, gen_salt('bf')));
                """

    values = [content["username"], content["password"]]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    return {"Code": OK_CODE}


##########################################################
# CONSULTAR LISTAS
##########################################################
@app.route("/consultar_saldo", methods=['POST'])
@auth_user
def consultar_saldo():

    content = request.get_json()

    conn = db_connection()
    cur = conn.cursor()

    decoded_token = jwt.decode(content['token'], app.config['SECRET_KEY'])

    cur.execute("SELECT CAST(CAST(saldo AS NUMERIC(8,2)) AS VARCHAR) FROM utilizadores WHERE id = %s;",
                (decoded_token["id"],))
    rows = cur.fetchall()
    conn.close()
    return {"Saldo": rows[0][0]}


##########################################################
# CONSULTAR TAREFAS
##########################################################
@app.route("/consultar_utilizador", methods=['POST'])
@auth_user
def consultar_utilizador():
    content = request.get_json()

    conn = db_connection()
    cur = conn.cursor()

    decoded_token = jwt.decode(content['token'], app.config['SECRET_KEY'])

    cur.execute("SELECT * FROM utilizadores WHERE id = %s;",
                (decoded_token["id"],))
    rows = cur.fetchall()

    conn.close()
    return jsonify({"Id": rows[0][1], "nome": rows[0][2], "e-mail": rows[0][4], "cargo": rows[0][6]})

##########################################################
# ACTUALIZAR UTILIZADOR
##########################################################


@app.route("/actualizar_utilizador", methods=['POST'])
@auth_user
def actualizar_utilizador():
    content = request.get_json()

    if "nome" not in content or "email" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})

    get_user_info = """
                UPDATE utilizadores SET nome = %s, email = %s WHERE id = %s;
                """
    decoded_token = jwt.decode(content['token'], app.config['SECRET_KEY'])
    values = [content["nome"], content["email"], decoded_token["id"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Utilizador não actualizado!"})
    return {"Code": OK_CODE}


##########################################################
# CARREGAR SALDO
##########################################################
@app.route("/carregar_saldo", methods=['POST'])
@auth_user
def carregar_saldo():
    content = request.get_json()

    if "n_identificacao" not in content or "saldo" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})

    get_user_info = """
                UPDATE utilizadores SET saldo = saldo + %s WHERE n_identificacao = %s;
                """

    values = [content["saldo"], content["n_identificacao"]]

    decoded_token = jwt.decode(content['token'], app.config['SECRET_KEY'])
    if(not decoded_token['administrador']):
        return jsonify({"Erro": "O utilizador não tem esses privilégios", "Code": FORBIDDEN_CODE})

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Saldo não carregado"})
    return {"Code": OK_CODE}

##########################################################
# DATABASE ACCESS
##########################################################


def db_connection():

    DATABASE_URL = os.environ.get(
        'postgres://uefznddxxshgrz:b9870e934cad95992efdad2d0b13fb4247b4f2aad0804a5b051a0545badb947b@ec2-34-247-172-149.eu-west-1.compute.amazonaws.com:5432/de2inhmnpsrf0t')
    db = psycopg2.connect(DATABASE_URL)
    return db


if __name__ == "__main__":

    app.run(port=8080, debug=True, threaded=True)
