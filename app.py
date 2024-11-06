from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import jwt
import datetime
from functools import wraps
app = Flask(__name__)
app.config['SECRET_KEY'] = 'seuSegredoJWT'  # Defina uma chave secreta real aqui

# Middleware para verificar o token
def verify_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'error': 'Nenhum token foi fornecido.'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.usuario = data
        except:
            return jsonify({'error': 'Falha ao autenticar o token.'}), 500
        return f(*args, **kwargs)
    return decorated


# Middleware para verificar token de admin
def verify_admin_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'error': 'Nenhum token foi fornecido.'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if data['tipo'] != 'admin':
                return jsonify({'error': 'Você não tem privilégios para a ação desejada.'}), 403
            request.usuario = data
        except:
            return jsonify({'error': 'Falha ao autenticar o token.'}), 500
        return f(*args, **kwargs)
    return decorated


# Rota para obter produtos
@app.route('/api/produtos', methods=['GET'])
@verify_token
def get_produtos():
    database = sqlite3.connect("produtos.db")
    cursor = database.cursor()
    cursor.execute("SELECT * FROM produtos")
    produtos = cursor.fetchall()
    
    produtos_json = []
    for produto in produtos:
        produto_json = { "id": produto[0], 
                         "nome": produto[1],
                         "preco": produto[2],
                         "estoque": produto[3]}
        produtos_json.append(produto_json)
    return produtos_json

# Rota para obter um produto por seu id.
@app.route('/api/produtos/<int:id>', methods=['GET'])
@verify_token
def get_produto(id):
    database = sqlite3.connect("produtos.db")
    cursor = database.cursor()
    cursor.execute(f"SELECT * FROM produtos WHERE id = {id}")
    produtos = cursor.fetchall()
    
    if len(produtos) == 0:
        return jsonify({"error": "Produto não encontrado"}), 404
    else:
        produto_json = { "id": produtos[0][0], 
                     "nome": produtos[0][1],
                     "preco": produtos[0][2],
                     "estoque": produtos[0][3]}
        return produto_json

# Rota para criar um produto
@app.route('/api/produtos', methods=['POST'])
@verify_admin_token
def create_produto():
    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({"error": "Forneça os dados em formato JSON"}), 415 

    if 'nome' in data and 'preco' in data and 'estoque' in data:
        database = sqlite3.connect("produtos.db")
        cursor = database.cursor()
        try:
            sql = "INSERT INTO produtos (nome, preco, estoque) VALUES (?, ?, ?)"
            result = cursor.execute(sql, (data['nome'], data['preco'], data['estoque']))
            database.commit()
            return jsonify({"info": "Produto cadastrado com sucesso."}) 
        except Exception as e:
            return jsonify({"error": "Erro interno no banco de dados."}), 500 
    else:
        return jsonify({"error": "Dados obrigatórios não foram fornecidos no corpo da requisição"}), 500 

#Rota de atualizar produto
@app.route('/api/produtos/<int:id>', methods=['PATCH'])
@verify_admin_token
def atualizar_produto(id):
    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({"error": "Forneça os dados em formato JSON"}), 415 


    if 'nome' in data or 'preco' in data or 'estoque' in data:
        database = sqlite3.connect("produtos.db")
        cursor = database.cursor()
        
        v_set = ""
        v_valores = []
        
        if 'nome' in data:
            v_set = "nome=?"
            v_valores.append(data['nome'])

        if 'preco' in data:
            if len(v_valores) > 0:
                v_set += ", "
            v_set += "preco=?"
            v_valores.append(data['preco'])
        
        if 'estoque' in data:
            if len(v_valores) > 0:
                v_set += ", "
            v_set += "estoque=?"
            v_valores.append(data['estoque'])

        sql = "UPDATE produtos SET " + v_set + " WHERE id=?"
        print(sql)
        v_valores.append(id)
        
        cursor.execute(sql, (v_valores))
        if cursor.rowcount > 0:
            database.commit()
            return jsonify({'message': 'Produto atualizado com sucesso!'})
        else:
            return jsonify({'message': 'Produto não encontrado.'}), 404

    else:
        return jsonify({"error": "Dados obrigatórios não foram fornecidos no corpo da requisição"}), 500 

@app.route('/api/produtos', methods=['PATCH', 'DELETE'])
@verify_admin_token
def deu_ruim():
    return jsonify({"error": "O id do produto a ser atualizado ou apagado não foi fornecido como parâmetro"}), 500 
    
# Rota para apagar um produto
@app.route('/api/produtos/<int:id>', methods=['DELETE'])
@verify_admin_token
def apagar_produto(id):
    database = sqlite3.connect("produtos.db")
    cursor = database.cursor()    
    cursor.execute("DELETE FROM produtos WHERE id = ?", (id,))
    if cursor.rowcount > 0:
        database.commit()
        return jsonify({}), 204
    else:
        return jsonify({'message': 'Produto não encontrado.'}), 404

# A PARTE USUARIOS
# Rota para criar um usuario com senha criptografada
@app.route('/api/usuarios', methods=['POST'])
@verify_admin_token
def create_usuario():
    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({"error": "Forneça os dados em formato JSON"}), 415 

    if 'username' in data and 'password' in data and 'tipo' in data:
        database = sqlite3.connect("produtos.db")
        cursor = database.cursor()
        password_crypted = generate_password_hash(data['password'], method='sha256')
        try:
            sql = "INSERT INTO usuarios (username, password, tipo) VALUES (?, ?, ?)"
            result = cursor.execute(sql, (data['username'], password_crypted, data['tipo']))
            database.commit()
            return jsonify({"info": "Usuário cadastrado com sucesso."}) 
        except Exception as e:
            return jsonify({"error": "Erro interno no banco de dados."}), 500 
    else:
        return jsonify({"error": "Dados obrigatórios não foram fornecidos no corpo da requisição"}), 500 

# Função para gerar token JWT
def generate_token(usuario):
    token = jwt.encode({'id': usuario[0], 
    'username': usuario[1], 
    'tipo': usuario[3], 
    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
    app.config['SECRET_KEY'], algorithm='HS256')
    return token


# Rota para LOGIN e GERAÇÃO DO TOKEN JWT
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({"error": "Forneça os dados em formato JSON"}), 415 

    if 'username' in data and 'password' in data:
        database = sqlite3.connect("produtos.db")
        cursor = database.cursor()
        sql = "SELECT id, username, password, tipo FROM usuarios WHERE username=?"
        cursor.execute(sql, (data['username'],))
        usuario = cursor.fetchone()
        if not usuario:
            return jsonify({"error":"Usuário não encontrado"}), 404
        else:
            if check_password_hash(usuario[2], data['password']):
                token = generate_token(usuario)
                return jsonify({'message': 'Login bem-sucedido!', 'token': token})
            else:
                return jsonify({"error": "Senha inválida"}), 401
    else:
        return jsonify({"error": "Dados obrigatórios não foram fornecidos no corpo da requisição"}), 500 

        
if __name__ == '__main__':
    app.run(port=3000)
