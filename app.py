from flask import Flask, request, jsonify
import sqlite3
app = Flask(__name__)

# Vamos fazer a consulta de produtos



# Rota para obter produtos
@app.route('/api/produtos', methods=['GET'])
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
def create_produto():
    data = request.get_json()
    database = sqlite3.connect("produtos.db")
    cursor = database.cursor()
    
    if 'nome' in data and 'preco' in data and 'estoque' in data:
        try:
            sql = "INSERT INTO produtos (nome, preco, estoque) VALUES (?, ?, ?)"
            result = cursor.execute(sql, (data['nome'], data['preco'], data['estoque']))
            database.commit()
            return jsonify({"info": "Produto cadastrado com sucesso."}) 
        except Exception as e:
            return jsonify({"error": "Erro interno no banco de dados."}), 500 
    else:
        return jsonify({"error": "Dados obrigatórios não foram fornecidos o corpo da requisição"}), 500 

if __name__ == '__main__':
    app.run(port=3000)
