"""
Sistema de Gerenciamento de Biblioteca - Back-end (Flask + SQLite + JWT)

Módulos (conforme Quadro 1 do artigo):
  01 Cadastro de livros      -> /api/livros
  02 Cadastro de usuários    -> /api/usuarios (leitores)
  03 Empréstimos             -> /api/emprestimos
  04 Devoluções              -> /api/emprestimos/<id>/devolucao
  05 Consulta ao acervo      -> /api/acervo

Segurança: senhas com hash (Werkzeug), autenticação por token JWT,
perfis de acesso (admin / bibliotecario), consultas SQL parametrizadas
e validação de todas as entradas.
"""
import os
import re
import sqlite3
import secrets
from datetime import datetime, timedelta, date
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("BIBLIOTECA_DB", os.path.join(BASE_DIR, "biblioteca.db"))
SECRET_FILE = os.path.join(BASE_DIR, ".secret_key")
MULTA_POR_DIA = 0.50
MAX_EMPRESTIMOS_ABERTOS = 3

app = Flask(__name__, static_folder="static", static_url_path="")


def _carregar_segredo():
    if os.environ.get("BIBLIOTECA_SECRET"):
        return os.environ["BIBLIOTECA_SECRET"]
    if os.path.exists(SECRET_FILE):
        return open(SECRET_FILE).read().strip()
    s = secrets.token_hex(32)
    with open(SECRET_FILE, "w") as f:
        f.write(s)
    return s


app.config["SECRET_KEY"] = _carregar_segredo()

# ---------------------------------------------------------------- banco ----
SCHEMA = """
CREATE TABLE IF NOT EXISTS operadores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    login TEXT NOT NULL UNIQUE,
    senha_hash TEXT NOT NULL,
    perfil TEXT NOT NULL CHECK (perfil IN ('admin','bibliotecario'))
);
CREATE TABLE IF NOT EXISTS livros (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titulo TEXT NOT NULL,
    autor TEXT NOT NULL,
    editora TEXT NOT NULL DEFAULT '',
    isbn TEXT UNIQUE,
    ano INTEGER,
    quantidade INTEGER NOT NULL CHECK (quantidade >= 0),
    criado_em TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    cpf TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    telefone TEXT NOT NULL DEFAULT '',
    ativo INTEGER NOT NULL DEFAULT 1,
    criado_em TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS emprestimos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    livro_id INTEGER NOT NULL REFERENCES livros(id),
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
    data_emprestimo TEXT NOT NULL,
    data_prevista TEXT NOT NULL,
    data_devolucao TEXT,
    multa REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_emp_livro ON emprestimos(livro_id);
CREATE INDEX IF NOT EXISTS idx_emp_usuario ON emprestimos(usuario_id);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def fechar_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    if db.execute("SELECT COUNT(*) FROM operadores").fetchone()[0] == 0:
        senha_inicial = os.environ.get("BIBLIOTECA_ADMIN_SENHA", "admin123")
        db.execute(
            "INSERT INTO operadores (nome, login, senha_hash, perfil) VALUES (?,?,?,?)",
            ("Administrador", "admin", generate_password_hash(senha_inicial), "admin"),
        )
    db.commit()
    db.close()


# ------------------------------------------------------------ utilidades ----
def agora():
    return datetime.now().isoformat(timespec="seconds")


def hoje():
    return date.today()


def erro(msg, codigo=400):
    return jsonify({"erro": msg}), codigo


def so_digitos(s):
    return re.sub(r"\D", "", s or "")


def cpf_valido(cpf):
    cpf = so_digitos(cpf)
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False
    for i in (9, 10):
        soma = sum(int(cpf[n]) * (i + 1 - n) for n in range(i))
        dv = (soma * 10) % 11 % 10
        if dv != int(cpf[i]):
            return False
    return True


def isbn_valido(isbn):
    d = re.sub(r"[\s-]", "", isbn or "")
    if len(d) == 10 and re.fullmatch(r"\d{9}[\dXx]", d):
        total = sum((10 - i) * (10 if c in "Xx" else int(c)) for i, c in enumerate(d))
        return total % 11 == 0
    if len(d) == 13 and d.isdigit():
        total = sum(int(c) * (1 if i % 2 == 0 else 3) for i, c in enumerate(d[:12]))
        return (10 - total % 10) % 10 == int(d[12])
    return False


def calcular_multa(data_prevista, data_ref):
    atraso = (data_ref - date.fromisoformat(data_prevista)).days
    return round(max(atraso, 0) * MULTA_POR_DIA, 2)


# ------------------------------------------------------------ autenticação --
def gerar_token(op):
    payload = {
        "sub": str(op["id"]),
        "nome": op["nome"],
        "perfil": op["perfil"],
        "exp": datetime.utcnow() + timedelta(hours=8),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def exige_login(*perfis):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return erro("Autenticação necessária.", 401)
            try:
                dados = jwt.decode(auth[7:], app.config["SECRET_KEY"], algorithms=["HS256"])
            except jwt.PyJWTError:
                return erro("Sessão inválida ou expirada.", 401)
            if perfis and dados["perfil"] not in perfis:
                return erro("Você não tem permissão para esta operação.", 403)
            g.operador = dados
            return fn(*a, **kw)
        return wrapper
    return deco


# tentativas de login (proteção simples contra força bruta)
_falhas = {}


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    login_ = str(d.get("login", "")).strip()
    senha = str(d.get("senha", ""))
    chave = (request.remote_addr, login_)
    tent = _falhas.get(chave, (0, datetime.min))
    if tent[0] >= 5 and datetime.now() - tent[1] < timedelta(minutes=5):
        return erro("Muitas tentativas. Aguarde alguns minutos.", 429)
    op = get_db().execute("SELECT * FROM operadores WHERE login = ?", (login_,)).fetchone()
    if not op or not check_password_hash(op["senha_hash"], senha):
        _falhas[chave] = (tent[0] + 1, datetime.now())
        return erro("Login ou senha incorretos.", 401)
    _falhas.pop(chave, None)
    return jsonify({"token": gerar_token(op), "nome": op["nome"], "perfil": op["perfil"]})


@app.get("/api/me")
@exige_login()
def me():
    return jsonify({"nome": g.operador["nome"], "perfil": g.operador["perfil"]})


# --------------------------------------------------------- operadores (admin)
@app.get("/api/operadores")
@exige_login("admin")
def listar_operadores():
    rows = get_db().execute("SELECT id, nome, login, perfil FROM operadores ORDER BY nome").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/operadores")
@exige_login("admin")
def criar_operador():
    d = request.get_json(silent=True) or {}
    nome = str(d.get("nome", "")).strip()
    login_ = str(d.get("login", "")).strip()
    senha = str(d.get("senha", ""))
    perfil = d.get("perfil", "bibliotecario")
    if len(nome) < 3:
        return erro("Informe o nome (mínimo 3 caracteres).")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", login_):
        return erro("Login deve ter 3 a 30 caracteres (letras, números, _ . -).")
    if len(senha) < 8:
        return erro("A senha deve ter pelo menos 8 caracteres.")
    if perfil not in ("admin", "bibliotecario"):
        return erro("Perfil inválido.")
    try:
        db = get_db()
        cur = db.execute(
            "INSERT INTO operadores (nome, login, senha_hash, perfil) VALUES (?,?,?,?)",
            (nome, login_, generate_password_hash(senha), perfil),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return erro("Já existe um operador com esse login.", 409)
    return jsonify({"id": cur.lastrowid, "nome": nome, "login": login_, "perfil": perfil}), 201


@app.delete("/api/operadores/<int:oid>")
@exige_login("admin")
def excluir_operador(oid):
    if str(oid) == g.operador["sub"]:
        return erro("Você não pode excluir o próprio usuário.")
    db = get_db()
    db.execute("DELETE FROM operadores WHERE id = ?", (oid,))
    db.commit()
    return "", 204


# ----------------------------------------------------------------- livros ---
def validar_livro(d):
    titulo = str(d.get("titulo", "")).strip()
    autor = str(d.get("autor", "")).strip()
    editora = str(d.get("editora", "")).strip()
    isbn = re.sub(r"[\s-]", "", str(d.get("isbn") or "")).upper() or None
    ano = d.get("ano")
    qtd = d.get("quantidade")
    if not titulo or len(titulo) > 200:
        return None, "Título é obrigatório (até 200 caracteres)."
    if not autor or len(autor) > 150:
        return None, "Autor é obrigatório (até 150 caracteres)."
    if len(editora) > 100:
        return None, "Editora muito longa."
    if isbn and not isbn_valido(isbn):
        return None, "ISBN inválido (use 10 ou 13 dígitos válidos)."
    if ano in ("", None):
        ano = None
    else:
        try:
            ano = int(ano)
        except (TypeError, ValueError):
            return None, "Ano inválido."
        if not 1000 <= ano <= hoje().year + 1:
            return None, "Ano fora do intervalo permitido."
    try:
        qtd = int(qtd)
    except (TypeError, ValueError):
        return None, "Quantidade de exemplares inválida."
    if qtd < 0 or qtd > 10000:
        return None, "Quantidade deve estar entre 0 e 10000."
    return dict(titulo=titulo, autor=autor, editora=editora, isbn=isbn, ano=ano, quantidade=qtd), None


SQL_ACERVO = """
SELECT l.*, l.quantidade - COALESCE(
         (SELECT COUNT(*) FROM emprestimos e WHERE e.livro_id = l.id AND e.data_devolucao IS NULL), 0
       ) AS disponiveis
FROM livros l
"""


@app.get("/api/livros")
@exige_login()
def listar_livros():
    q = request.args.get("q", "").strip()
    sql, params = SQL_ACERVO, []
    if q:
        sql += " WHERE l.titulo LIKE ? OR l.autor LIKE ? OR l.editora LIKE ? OR l.isbn LIKE ?"
        params = [f"%{q}%"] * 4
    sql += " ORDER BY l.titulo COLLATE NOCASE"
    return jsonify([dict(r) for r in get_db().execute(sql, params).fetchall()])


@app.get("/api/livros/<int:lid>")
@exige_login()
def obter_livro(lid):
    r = get_db().execute(SQL_ACERVO + " WHERE l.id = ?", (lid,)).fetchone()
    return jsonify(dict(r)) if r else erro("Livro não encontrado.", 404)


@app.post("/api/livros")
@exige_login()
def criar_livro():
    dados, msg = validar_livro(request.get_json(silent=True) or {})
    if msg:
        return erro(msg)
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO livros (titulo, autor, editora, isbn, ano, quantidade, criado_em) VALUES (?,?,?,?,?,?,?)",
            (dados["titulo"], dados["autor"], dados["editora"], dados["isbn"], dados["ano"], dados["quantidade"], agora()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return erro("Já existe um livro com esse ISBN.", 409)
    return jsonify(dict(db.execute(SQL_ACERVO + " WHERE l.id = ?", (cur.lastrowid,)).fetchone())), 201


@app.put("/api/livros/<int:lid>")
@exige_login()
def atualizar_livro(lid):
    dados, msg = validar_livro(request.get_json(silent=True) or {})
    if msg:
        return erro(msg)
    db = get_db()
    atual = db.execute(SQL_ACERVO + " WHERE l.id = ?", (lid,)).fetchone()
    if not atual:
        return erro("Livro não encontrado.", 404)
    emprestados = atual["quantidade"] - atual["disponiveis"]
    if dados["quantidade"] < emprestados:
        return erro(f"Há {emprestados} exemplar(es) emprestado(s); a quantidade não pode ser menor.")
    try:
        db.execute(
            "UPDATE livros SET titulo=?, autor=?, editora=?, isbn=?, ano=?, quantidade=? WHERE id=?",
            (dados["titulo"], dados["autor"], dados["editora"], dados["isbn"], dados["ano"], dados["quantidade"], lid),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return erro("Já existe um livro com esse ISBN.", 409)
    return jsonify(dict(db.execute(SQL_ACERVO + " WHERE l.id = ?", (lid,)).fetchone()))


@app.delete("/api/livros/<int:lid>")
@exige_login()
def excluir_livro(lid):
    db = get_db()
    if db.execute("SELECT 1 FROM emprestimos WHERE livro_id = ?", (lid,)).fetchone():
        return erro("Livro possui histórico de empréstimos e não pode ser excluído. Zere a quantidade, se necessário.", 409)
    cur = db.execute("DELETE FROM livros WHERE id = ?", (lid,))
    db.commit()
    return ("", 204) if cur.rowcount else erro("Livro não encontrado.", 404)


# --------------------------------------------------------------- usuários ---
def validar_usuario(d):
    nome = str(d.get("nome", "")).strip()
    cpf = so_digitos(d.get("cpf"))
    email = str(d.get("email", "")).strip().lower()
    tel = so_digitos(d.get("telefone"))
    if len(nome) < 3 or len(nome) > 150:
        return None, "Nome é obrigatório (3 a 150 caracteres)."
    if not cpf_valido(cpf):
        return None, "CPF inválido."
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 150:
        return None, "E-mail inválido."
    if tel and not 10 <= len(tel) <= 11:
        return None, "Telefone deve ter DDD + número (10 ou 11 dígitos)."
    return dict(nome=nome, cpf=cpf, email=email, telefone=tel), None


@app.get("/api/usuarios")
@exige_login()
def listar_usuarios():
    q = request.args.get("q", "").strip()
    sql = """SELECT u.*, (SELECT COUNT(*) FROM emprestimos e
                          WHERE e.usuario_id = u.id AND e.data_devolucao IS NULL) AS emprestimos_abertos
             FROM usuarios u"""
    params = []
    if q:
        sql += " WHERE u.nome LIKE ? OR u.cpf LIKE ? OR u.email LIKE ?"
        params = [f"%{q}%", f"%{so_digitos(q) or q}%", f"%{q}%"]
    sql += " ORDER BY u.nome COLLATE NOCASE"
    return jsonify([dict(r) for r in get_db().execute(sql, params).fetchall()])


@app.post("/api/usuarios")
@exige_login()
def criar_usuario():
    dados, msg = validar_usuario(request.get_json(silent=True) or {})
    if msg:
        return erro(msg)
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO usuarios (nome, cpf, email, telefone, criado_em) VALUES (?,?,?,?,?)",
            (dados["nome"], dados["cpf"], dados["email"], dados["telefone"], agora()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return erro("Já existe um usuário com esse CPF.", 409)
    return jsonify(dict(db.execute("SELECT * FROM usuarios WHERE id = ?", (cur.lastrowid,)).fetchone())), 201


@app.put("/api/usuarios/<int:uid>")
@exige_login()
def atualizar_usuario(uid):
    d = request.get_json(silent=True) or {}
    dados, msg = validar_usuario(d)
    if msg:
        return erro(msg)
    ativo = 1 if d.get("ativo", True) else 0
    db = get_db()
    if not db.execute("SELECT 1 FROM usuarios WHERE id = ?", (uid,)).fetchone():
        return erro("Usuário não encontrado.", 404)
    if not ativo and db.execute(
        "SELECT 1 FROM emprestimos WHERE usuario_id = ? AND data_devolucao IS NULL", (uid,)
    ).fetchone():
        return erro("Usuário possui empréstimos em aberto e não pode ser inativado.", 409)
    try:
        db.execute(
            "UPDATE usuarios SET nome=?, cpf=?, email=?, telefone=?, ativo=? WHERE id=?",
            (dados["nome"], dados["cpf"], dados["email"], dados["telefone"], ativo, uid),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return erro("Já existe um usuário com esse CPF.", 409)
    return jsonify(dict(db.execute("SELECT * FROM usuarios WHERE id = ?", (uid,)).fetchone()))


@app.delete("/api/usuarios/<int:uid>")
@exige_login()
def excluir_usuario(uid):
    db = get_db()
    if db.execute("SELECT 1 FROM emprestimos WHERE usuario_id = ?", (uid,)).fetchone():
        return erro("Usuário possui histórico de empréstimos. Inative-o em vez de excluir.", 409)
    cur = db.execute("DELETE FROM usuarios WHERE id = ?", (uid,))
    db.commit()
    return ("", 204) if cur.rowcount else erro("Usuário não encontrado.", 404)


# ------------------------------------------------------------- empréstimos --
SQL_EMP = """
SELECT e.*, l.titulo AS livro_titulo, u.nome AS usuario_nome
FROM emprestimos e
JOIN livros l ON l.id = e.livro_id
JOIN usuarios u ON u.id = e.usuario_id
"""


def serializa_emp(r):
    d = dict(r)
    if d["data_devolucao"]:
        d["situacao"] = "devolvido"
        d["multa_atual"] = d["multa"]
    else:
        atrasado = date.fromisoformat(d["data_prevista"]) < hoje()
        d["situacao"] = "atrasado" if atrasado else "em_andamento"
        d["multa_atual"] = calcular_multa(d["data_prevista"], hoje())
    return d


@app.get("/api/emprestimos")
@exige_login()
def listar_emprestimos():
    status = request.args.get("status", "")
    sql = SQL_EMP
    if status in ("abertos", "atrasados"):
        sql += " WHERE e.data_devolucao IS NULL"
    elif status == "devolvidos":
        sql += " WHERE e.data_devolucao IS NOT NULL"
    sql += " ORDER BY e.id DESC"
    lista = [serializa_emp(r) for r in get_db().execute(sql).fetchall()]
    if status == "atrasados":
        lista = [e for e in lista if e["situacao"] == "atrasado"]
    return jsonify(lista)


@app.post("/api/emprestimos")
@exige_login()
def criar_emprestimo():
    d = request.get_json(silent=True) or {}
    try:
        livro_id, usuario_id = int(d.get("livro_id")), int(d.get("usuario_id"))
        prazo_dias = int(d.get("prazo_dias"))
    except (TypeError, ValueError):
        return erro("Selecione o livro o usuário e informe o prazo.")
        if prazo_dias < 1:
            return erro("0 informe um prazo de pelo menos 1 dia. ")
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        livro = db.execute(SQL_ACERVO + " WHERE l.id = ?", (livro_id,)).fetchone()
        usuario = db.execute("SELECT * FROM usuarios WHERE id = ?", (usuario_id,)).fetchone()
        if not livro:
            db.rollback(); return erro("Livro não encontrado.", 404)
        if not usuario:
            db.rollback(); return erro("Usuário não encontrado.", 404)
        if not usuario["ativo"]:
            db.rollback(); return erro("Usuário inativo não pode realizar empréstimos.", 409)
        if livro["disponiveis"] < 1:
            db.rollback(); return erro("Não há exemplares disponíveis deste livro.", 409)
        abertos = db.execute(
            "SELECT COUNT(*) FROM emprestimos WHERE usuario_id = ? AND data_devolucao IS NULL", (usuario_id,)
        ).fetchone()[0]
        if abertos >= MAX_EMPRESTIMOS_ABERTOS:
            db.rollback(); return erro(f"Limite de {MAX_EMPRESTIMOS_ABERTOS} empréstimos em aberto atingido.", 409)
        if db.execute(
            "SELECT 1 FROM emprestimos WHERE usuario_id = ? AND livro_id = ? AND data_devolucao IS NULL",
            (usuario_id, livro_id),
        ).fetchone():
            db.rollback(); return erro("Este usuário já está com um exemplar deste livro.", 409)
        atrasado = [
            1 for r in db.execute(
                "SELECT data_prevista FROM emprestimos WHERE usuario_id = ? AND data_devolucao IS NULL", (usuario_id,)
            ).fetchall() if date.fromisoformat(r["data_prevista"]) < hoje()
        ]
        if atrasado:
            db.rollback(); return erro("Usuário possui empréstimo em atraso. Regularize antes de um novo empréstimo.", 409)
        cur = db.execute(
            "INSERT INTO emprestimos (livro_id, usuario_id, data_emprestimo, data_prevista) VALUES (?,?,?,?)",
            (livro_id, usuario_id, hoje().isoformat(), (hoje() + timedelta(days=prazo_dias)).isoformat()),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        return erro("Erro ao registrar o empréstimo.", 500)
    return jsonify(serializa_emp(db.execute(SQL_EMP + " WHERE e.id = ?", (cur.lastrowid,)).fetchone())), 201


@app.post("/api/emprestimos/<int:eid>/devolucao")
@exige_login()
def devolver(eid):
    db = get_db()
    e = db.execute("SELECT * FROM emprestimos WHERE id = ?", (eid,)).fetchone()
    if not e:
        return erro("Empréstimo não encontrado.", 404)
    if e["data_devolucao"]:
        return erro("Este empréstimo já foi devolvido.", 409)
    multa = calcular_multa(e["data_prevista"], hoje())
    db.execute("UPDATE emprestimos SET data_devolucao = ?, multa = ? WHERE id = ?", (hoje().isoformat(), multa, eid))
    db.commit()
    return jsonify(serializa_emp(db.execute(SQL_EMP + " WHERE e.id = ?", (eid,)).fetchone()))


# ---------------------------------------------------------------- acervo ----
@app.get("/api/acervo")
@exige_login()
def consulta_acervo():
    """Consulta ao acervo com disponibilidade (filtro opcional: apenas disponíveis)."""
    q = request.args.get("q", "").strip()
    so_disp = request.args.get("disponiveis") == "1"
    sql = f"SELECT * FROM ({SQL_ACERVO}) t WHERE 1=1"
    params = []
    if q:
        sql += " AND (titulo LIKE ? OR autor LIKE ? OR editora LIKE ? OR isbn LIKE ?)"
        params += [f"%{q}%"] * 4
    if so_disp:
        sql += " AND disponiveis > 0"
    sql += " ORDER BY titulo COLLATE NOCASE"
    return jsonify([dict(r) for r in get_db().execute(sql, params).fetchall()])


@app.get("/api/resumo")
@exige_login()
def resumo():
    db = get_db()
    abertos = db.execute("SELECT data_prevista FROM emprestimos WHERE data_devolucao IS NULL").fetchall()
    return jsonify({
        "titulos": db.execute("SELECT COUNT(*) FROM livros").fetchone()[0],
        "exemplares": db.execute("SELECT COALESCE(SUM(quantidade),0) FROM livros").fetchone()[0],
        "usuarios": db.execute("SELECT COUNT(*) FROM usuarios WHERE ativo = 1").fetchone()[0],
        "emprestimos_abertos": len(abertos),
        "atrasados": sum(1 for r in abertos if date.fromisoformat(r["data_prevista"]) < hoje()),
    })


# ------------------------------------------------------------- front-end ----
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.after_request
def cabecalhos_seguranca(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
