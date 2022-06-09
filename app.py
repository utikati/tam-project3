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
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "No token provided"}), UNAUTHORIZED_CODE

        try:
            decoded_token = jwt.decode(
                token, app.config['SECRET_KEY'])
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
                FROM useron
                WHERE user_name = %s AND user_password = crypt(%s, user_password);
                """

    values = [content["username"], content["password"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
                print(rows)
                token = jwt.encode({
                    'id': rows[0][0],
                    'username': rows[0][1],
                    'expiration': str(datetime.utcnow() + timedelta(hours=1))
                }, app.config['SECRET_KEY'])
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Utilizador não encontrado"})
    return jsonify({"Code": OK_CODE, 'Token': token.decode('utf-8')})

##########################################################
# Verificar Existência de Utilizador
##########################################################


def verificar_username(username):

    get_user_info = """
                SELECT COUNT(*) AS VARCHAR
                FROM useron
                WHERE user_name = %s;
                """
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, [username])
                rows = cursor.fetchall()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return 0

    if rows[0][0] == 0:
        return False
    else:
        return True

##########################################################
# REGISTO DE UTILIZADOR
##########################################################


@app.route("/registar_utilizador", methods=['POST'])
def registar_utilizador():
    content = request.get_json()
    username = content["username"]

    if "username" not in content or "password" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})
    if verificar_username(username):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Utilizador já existe"})

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
# LISTAS
##########################################################

##########################################################

# Acesso a lista
def acesso_lista(lista_id, user_id):
    get_user_info = """
                SELECT COUNT(*)
                FROM lists
                WHERE id_list = %s AND user_id_user = %s;
                """
    values = [lista_id, user_id]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return True

    if rows[0][0] == 0:
        # Condição vai dar true a indicar que não tem acesso a lista (para entrar no if)
        return True
    else:
        return False


# Verificar Numero de Tarefas por causa de apagar listas

def verificar_tarefas_lista(list_id):
    get_user_info = """
                    SELECT COUNT(*)
                    FROM tasks
                    WHERE list_id = %s;
                    """

    values = [list_id]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return False

    if not rows:
        return False

    if rows[0][0] == 0:
        return False
    else:
        return True

##################################
# Verificar Existência de Lista


def verificar_lista(list_id):
    get_user_info = """
                    SELECT COUNT(*)
                    FROM lists
                    WHERE id_list = %s;
                    """

    values = [list_id]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return True

    if not rows:
        return True

    if rows[0][0] == 0:
        return True
    else:
        return False


#####################################################
# Lista de todas as listas
@app.route("/listas", methods=['GET'])
@auth_user
def listas():
    content = request.get_json()
    token = content["token"]
    decoded_token = jwt.decode(token, app.config['SECRET_KEY'])

    get_user_info = """
                    SELECT *
                    FROM lists
                    WHERE user_id_user = %s;
                    """

    values = [decoded_token["id"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})

    if not rows:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Não existem listas"})

    return jsonify({"Code": OK_CODE, "Listas": rows})

########################################################
# Inserir lista


@app.route("/listas", methods=['POST'])
@auth_user
def inserir_lista():
    content = request.get_json()
    token = content["token"]
    decoded_token = jwt.decode(token, app.config['SECRET_KEY'])
    user_id = decoded_token["id"]

    if "list_name" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})

    get_user_info = """
                    INSERT INTO lists(user_id_user, list_name) 
                    VALUES(%s, %s);
                    """

    values = [user_id, content["list_name"]]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    return {"Code": OK_CODE}
####################################

# Apagar lista


@app.route("/listas/<int:list_id>", methods=['DELETE'])
@auth_user
def apagar_lista(list_id):
    content = request.get_json()
    token = content["token"]
    decoded_token = jwt.decode(token, app.config['SECRET_KEY'])
    user_id = decoded_token["id"]
    if verificar_tarefas_lista(list_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Lista não pode ser apagada"})
    if verificar_lista(list_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Lista não existe"})
    get_user_info = """
                    DELETE FROM lists
                    WHERE user_id_user = %s AND id_list = %s;
                    """

    values = [user_id, list_id]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    return {"Code": OK_CODE}

############################################
# Actualizar lista


@app.route("/listas/<int:list_id>", methods=['PUT'])
@auth_user
def actualizar_lista(list_id):
    content = request.get_json()
    token = content["token"]
    decoded_token = jwt.decode(token, app.config['SECRET_KEY'])
    user_id = decoded_token["id"]

    if "list_name" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})
    if verificar_lista(list_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Lista não existe"})

    get_user_info = """
                    UPDATE lists
                    SET list_name = %s
                    WHERE user_id_user = %s AND id_list = %s;
                    """

    values = [content["list_name"], user_id, list_id]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    return {"Code": OK_CODE}

###################################################################
# TAREFAS
###################################################################

###########################################
# Tarefas de uma lista


@app.route("/listas/<int:list_id>/tarefas", methods=['GET'])
@auth_user
def tarefas_lista(list_id):
    content = request.get_json()
    token = content["token"]
    decoded_token = jwt.decode(token, app.config['SECRET_KEY'])
    user_id = decoded_token["id"]

    if verificar_lista(list_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Lista não existe"})
    if acesso_lista(list_id, user_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Acesso negado"})

    get_user_info = """
                    SELECT id_task, description, deadline, stateontime, concluded, checkhour, lists_id_list
                    FROM tasks, lists
                    WHERE tasks.lists_id_list = %s AND tasks.lists_id_list = lists.id_list AND lists.user_id_user = %s;
                    """

    values = [list_id, user_id]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})

    if not rows:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Não existem tarefas"})

    return jsonify({"Code": OK_CODE, "Tarefas": rows})

###########################################
# Inserir tarefa


@app.route("/listas/<int:list_id>/tarefas", methods=['POST'])
@auth_user
def inserir_tarefa(list_id):
    content = request.get_json()
    token = content["token"]
    decoded_token = jwt.decode(token, app.config['SECRET_KEY'])
    user_id = decoded_token["id"]

    if "task_description" not in content or "task_deadline" not in content or "task_stateontime" not in content or "task_concluded" not in content or "task_checkhour" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})
    if verificar_lista(list_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Lista não existe"})
    if acesso_lista(list_id, user_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Acesso negado"})

    get_user_info = """
                    INSERT INTO tasks(description, deadline, stateontime, concluded, checkhour, lists_id_list) 
                    VALUES(%s, %s, %s, %s, %s, %s);
                    """

    values = [content["task_description"], content["task_deadline"],
              content["task_stateontime"], content["task_concluded"], content["task_checkhour"], list_id]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    return {"Code": OK_CODE}

################################################################
# Todas tarefas do utilizador


@app.route("/listas/tarefas", methods=['GET'])
@auth_user
def tarefas_user():
    content = request.get_json()
    token = content["token"]
    decoded_token = jwt.decode(token, app.config['SECRET_KEY'])
    user_id = decoded_token["id"]

    get_user_info = """
                    SELECT *
                    FROM tasks, lists
                    WHERE tasks.lists_id_list = lists.id_list AND lists.user_id_user = %s;
                    """

    values = [user_id]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})

    if not rows:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Não existem tarefas"})

    return jsonify({"Code": OK_CODE, "Tarefas": rows})

#####################################################################################
# Actualizar tarefa


@app.route("/listas/<int:list_id>/tarefas/<int:task_id>", methods=['PUT'])
@auth_user
def actualizar_tarefa(list_id, task_id):
    content = request.get_json()
    token = content["token"]
    decoded_token = jwt.decode(token, app.config['SECRET_KEY'])
    user_id = decoded_token["id"]

    if verificar_lista(list_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Lista não existe"})
    if acesso_lista(list_id, user_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Acesso negado"})

    if "task_description" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})

    get_user_info = """
                    UPDATE tasks
                    SET description = %s, deadline = %s, stateontime = %s, concluded = %s, checkhour = %s
                    WHERE id_task = %s;
                    """

    values = [content["task_description"], content["task_deadline"],
              content["task_stateontime"], content["task_concluded"], content["task_checkhour"], task_id]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    return {"Code": OK_CODE}

############################################################
# Eliminar tarefa


@app.route("/listas/<int:list_id>/tarefas/<int:task_id>", methods=['DELETE'])
@auth_user
def eliminar_tarefa(list_id, task_id):
    content = request.get_json()
    token = content["token"]
    decoded_token = jwt.decode(token, app.config['SECRET_KEY'])
    user_id = decoded_token["id"]

    if verificar_lista(list_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Lista não existe"})
    if acesso_lista(list_id, user_id):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Acesso negado"})

    get_user_info = """
                    DELETE FROM tasks
                    WHERE id_task = %s;
                    """
    values = [task_id]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    return {"Code": OK_CODE}


##########################################################
# DATABASE ACCESS
##########################################################


def db_connection():

    db = psycopg2.connect(host="ec2-34-247-172-149.eu-west-1.compute.amazonaws.com", database="de2inhmnpsrf0t",
                          user="uefznddxxshgrz", password="b9870e934cad95992efdad2d0b13fb4247b4f2aad0804a5b051a0545badb947b",)
    return db


if __name__ == "__main__":

    app.run(port=8080, debug=True, threaded=True)
