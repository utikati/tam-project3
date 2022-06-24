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

app.config['SECRET_KEY'] = os.environ.get('SECRET')

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
                return jsonify({"Erro": "O Token expirou!"}), NOT_FOUND

        except Exception as e:
            return jsonify({'Erro': 'Token inválido'}), FORBIDDEN_CODE

        request.user_id = decoded_token['id']

        return func(*args, **kwargs)
    return decorated


##########################################################
# LOGIN
##########################################################
@app.route("/login", methods=['POST'])
def login():
    content = request.get_json()

    if "username" not in content or "password" not in content:
        return jsonify({"Erro": "Parâmetros inválidos"}), BAD_REQUEST_CODE

    get_user_info = """
                SELECT *
                FROM useron
                WHERE user_name = %s AND user_password = crypt(%s, user_password);
                """

    values = [content["username"], content["password"]]
    # timedelta(hours=1)
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()

                token = jwt.encode({
                    'id': rows[0][0],
                    'username': rows[0][1],
                    'expiration': str(datetime.utcnow() + timedelta(hours=1))
                }, app.config['SECRET_KEY'])
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        conn.close()
        return jsonify({"Erro": "Utilizador não encontrado"}), NOT_FOUND_CODE
    return jsonify({'Token': token.decode('utf-8')}), OK_CODE

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
        conn.close()
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
        return jsonify({"Erro": "Parâmetros inválidos"}), BAD_REQUEST_CODE
    if verificar_username(username):
        return jsonify({"Erro": "Utilizador já existe"}), BAD_REQUEST_CODE

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
        conn.close()
        print(error)
        return jsonify({"Erro": str(error)}), NOT_FOUND_CODE
    return {}, SUCCESS_CODE


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
        conn.close()
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
                    WHERE lists_id_list = %s;
                    """

    values = [list_id]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        conn.close()
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
        conn.close()
        print(error)
        return True

    if not rows:
        return True

    if rows[0][0] == 0:
        return True
    else:
        return False


#############################################################################################
# Lista de todas as listas
@app.route("/listas", methods=['GET'])
@auth_user
def listas():
    get_user_info = """
                    SELECT *
                    FROM lists
                    WHERE user_id_user = %s;
                    """

    values = [request.user_id]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        conn.close()
        print(error)
        return jsonify({"Erro": str(error)}), NOT_FOUND_CODE

    if not rows:
        return jsonify({"Erro": "Não existem listas"}), NOT_FOUND_CODE

    Listas = []
    for row in rows:
        Listas.append(
            {"id_list": row[0], "list_name": row[1], "user_id_user": row[2]})

    return jsonify(Listas), OK_CODE

########################################################
# Inserir lista


@app.route("/listas", methods=['POST'])
@auth_user
def inserir_lista():
    content = request.get_json()
    user_id = request.user_id

    if "list_name" not in content:
        return jsonify({"Erro": "Parâmetros inválidos"}), BAD_REQUEST_CODE

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
        conn.close()
        return jsonify({"Erro": str(error)}), NOT_FOUND_CODE
    return {}, SUCCESS_CODE
####################################

# Apagar lista


@app.route("/listas/<int:list_id>", methods=['DELETE'])
@auth_user
def apagar_lista(list_id):
    user_id = request.user_id
    if verificar_tarefas_lista(list_id):

        return jsonify({"Erro": "Lista não pode ser apagada"}), BAD_REQUEST_CODE
    if verificar_lista(list_id):

        return jsonify({"Erro": "Lista não existe"}), BAD_REQUEST_CODE
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
        conn.close()
        return jsonify({"Erro": str(error)}), NOT_FOUND_CODE
    return {}, OK_CODE

############################################
# Actualizar lista


@app.route("/listas/<int:list_id>", methods=['PUT'])
@auth_user
def actualizar_lista(list_id):
    content = request.get_json()
    user_id = request.user_id

    if "list_name" not in content:
        return jsonify({"Erro": "Parâmetros inválidos"}), BAD_REQUEST_CODE
    if verificar_lista(list_id):
        return jsonify({"Erro": "Lista não existe"}), BAD_REQUEST_CODE

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
        conn.close()
        return jsonify({"Erro": str(error)}), NOT_FOUND_CODE
    return {}, OK_CODE

###################################################################
# TAREFAS
###################################################################

###########################################
# Tarefas de uma lista


@app.route("/listas/<int:list_id>/tarefas", methods=['GET'])
@auth_user
def tarefas_lista(list_id):
    user_id = request.user_id

    if verificar_lista(list_id):
        return jsonify({"Erro": "Lista não existe"}), BAD_REQUEST_CODE
    if acesso_lista(list_id, user_id):
        return jsonify({"Erro": "Acesso negado"}), BAD_REQUEST_CODE

    get_user_info = """
                    SELECT id_task, description, deadline, stateontime, concluded, checkhour, lists_id_list, tasks.listname
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
        conn.close()
        print(error)
        return jsonify({"Erro": str(error)}), NOT_FOUND_CODE

    if not rows:
        return jsonify({"Erro": "Não existem tarefas"}), NOT_FOUND_CODE

    Listas = []

    for row in rows:
        Listas.append(
            {"id_task": row[0], "description": row[1], "deadline": row[2], "stateontime": row[3], "concluded": row[4], "checkhour": row[5], "lists_id_list": row[6], "listname": row[7]})

    return jsonify(Listas), OK_CODE

###########################################
# Inserir tarefa


@app.route("/listas/<int:list_id>/tarefas", methods=['POST'])
@auth_user
def inserir_tarefa(list_id):
    content = request.get_json()
    user_id = request.user_id

    if "description" not in content or "deadline" not in content or "concluded" not in content or "checkhour" not in content:
        return jsonify({"Erro": "Parâmetros inválidos"}), BAD_REQUEST_CODE
    if verificar_lista(list_id):
        return jsonify({"Erro": "Lista não existe"}), BAD_REQUEST_CODE
    if acesso_lista(list_id, user_id):

        return jsonify({"Erro": "Acesso negado"}), BAD_REQUEST_CODE

    get_user_info = """
                    INSERT INTO tasks(description, deadline, stateontime, concluded, checkhour, lists_id_list, listname) 
                    VALUES(%s, %s, %s, %s, %s, %s, %s);
                    """

    values = [content["description"], content["deadline"],
              content["stateontime"], content["concluded"], content["checkhour"], list_id, content["listname"]]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        conn.close()
        return jsonify({"Erro": str(error)}), NOT_FOUND_CODE
    return {}, SUCCESS_CODE

################################################################
# Todas tarefas do utilizador


@app.route("/listas/tarefas", methods=['GET'])
@auth_user
def tarefas_user():

    user_id = request.user_id

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
        conn.close()
        print(error)
        return jsonify({"Erro": str(error)}), NOT_FOUND_CODE

    if not rows:
        return jsonify({"Erro": "Não existem tarefas"}), NOT_FOUND_CODE

    Listas = []

    for row in rows:
        Listas.append(
            {"id_task": row[0], "description": row[1], "deadline": row[2], "stateontime": row[3], "concluded": row[4], "checkhour": row[5], "lists_id_list": row[6], "listname": row[7]})

    return jsonify(Listas), OK_CODE

#####################################################################################
# Actualizar tarefa


@app.route("/listas/<int:list_id>/tarefas/<int:task_id>", methods=['PUT'])
@auth_user
def actualizar_tarefa(list_id, task_id):
    content = request.get_json()
    user_id = request.user_id

    if verificar_lista(list_id):
        return jsonify({"Erro": "Lista não existe"}), BAD_REQUEST_CODE
    if acesso_lista(list_id, user_id):
        return jsonify({"Erro": "Acesso negado"}), BAD_REQUEST_CODE

    if "description" not in content:
        print("description")
        return jsonify({"Erro": "Parâmetros inválidos"}), BAD_REQUEST_CODE

    if "deadline" not in content:
        print("deadline")
        return jsonify({"Erro": "Parâmetros inválidos"}), BAD_REQUEST_CODE

    if "stateontime" not in content:
        print("stateontime")
        return jsonify({"Erro": "Parâmetros inválidos"}), BAD_REQUEST_CODE

    if "concluded" not in content:
        print("concluded")
        return jsonify({"Erro": "Parâmetros inválidos"}), BAD_REQUEST_CODE

    if "checkhour" not in content:
        print("checkhour")
        return jsonify({"Erro": "Parâmetros inválidos"}), BAD_REQUEST_CODE

    get_user_info = """
                    UPDATE tasks
                    SET description = %s, deadline = %s, stateontime = %s, concluded = %s, checkhour = %s, listname = %s
                    WHERE id_task = %s;
                    """

    values = [content["description"], content["deadline"],
              content["stateontime"], content["concluded"], content["checkhour"], content["listname"], task_id]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        conn.close()
        return jsonify({"Erro": str(error)}), NOT_FOUND_CODE
    return {}, OK_CODE

############################################################
# Eliminar tarefa


@app.route("/listas/<int:list_id>/tarefas/<int:task_id>", methods=['DELETE'])
@auth_user
def eliminar_tarefa(list_id, task_id):
    user_id = request.user_id

    if verificar_lista(list_id):
        return jsonify({"Erro": "Lista não existe"}), BAD_REQUEST_CODE
    if acesso_lista(list_id, user_id):
        return jsonify({"Erro": "Acesso negado"}), BAD_REQUEST_CODE

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
        conn.close()
        return jsonify({"Erro": str(error)}), NOT_FOUND_CODE
    return {}, OK_CODE


##########################################################
# DATABASE ACCESS
##########################################################


def db_connection():

    DATABASE_URL = os.environ.get('DATABASE_URL')

    # host="ec2-34-247-172-149.eu-west-1.compute.amazonaws.com", database="de2inhmnpsrf0t",
    # user="uefznddxxshgrz", password="b9870e934cad95992efdad2d0b13fb4247b4f2aad0804a5b051a0545badb947b"

    db = psycopg2.connect(DATABASE_URL)
    return db


if __name__ == "__main__":

    app.run(port=8080, debug=True, threaded=True)
