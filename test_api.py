"""Testes funcionais da API (rode: python test_api.py)."""
import os, tempfile, sqlite3
from datetime import date, timedelta

os.environ["BIBLIOTECA_DB"] = os.path.join(tempfile.mkdtemp(), "teste.db")
os.environ["BIBLIOTECA_SECRET"] = "segredo-de-teste"
import app as A

c = A.app.test_client()
ok = 0

def check(nome, cond):
    global ok
    assert cond, f"FALHOU: {nome}"
    ok += 1
    print(f"  ok - {nome}")

r = c.get("/api/livros"); check("sem token -> 401", r.status_code == 401)
r = c.post("/api/login", json={"login": "admin", "senha": "errada"}); check("login inválido -> 401", r.status_code == 401)
r = c.post("/api/login", json={"login": "admin", "senha": "admin123"}); check("login válido", r.status_code == 200)
H = {"Authorization": "Bearer " + r.json["token"]}

# operador comum não acessa área admin
c.post("/api/operadores", headers=H, json={"nome": "Maria Silva", "login": "maria", "senha": "senha1234", "perfil": "bibliotecario"})
tk = c.post("/api/login", json={"login": "maria", "senha": "senha1234"}).json["token"]
HM = {"Authorization": "Bearer " + tk}
check("bibliotecário bloqueado em /operadores -> 403", c.get("/api/operadores", headers=HM).status_code == 403)

# livros
livro = {"titulo": "Dom Casmurro", "autor": "Machado de Assis", "editora": "Garnier", "isbn": "9788535902778", "ano": 1899, "quantidade": 2}
r = c.post("/api/livros", headers=H, json=livro); check("criar livro", r.status_code == 201 and r.json["disponiveis"] == 2)
lid = r.json["id"]
check("ISBN duplicado -> 409", c.post("/api/livros", headers=H, json=livro).status_code == 409)
check("ISBN inválido -> 400", c.post("/api/livros", headers=H, json={**livro, "isbn": "1234567890123"}).status_code == 400)
check("quantidade negativa -> 400", c.post("/api/livros", headers=H, json={**livro, "isbn": "", "quantidade": -1}).status_code == 400)
check("busca por autor", len(c.get("/api/livros?q=machado", headers=H).json) == 1)
check("injeção SQL tratada como texto", c.get("/api/livros?q=' OR 1=1 --", headers=H).json == [])

# usuários
r = c.post("/api/usuarios", headers=H, json={"nome": "João Pereira", "cpf": "529.982.247-25", "email": "joao@x.com", "telefone": "(86) 99999-0000"})
check("criar usuário", r.status_code == 201); uid = r.json["id"]
check("CPF inválido -> 400", c.post("/api/usuarios", headers=H, json={"nome": "Fulano", "cpf": "111.111.111-11", "email": "a@b.com"}).status_code == 400)
check("CPF duplicado -> 409", c.post("/api/usuarios", headers=H, json={"nome": "Outro", "cpf": "52998224725", "email": "o@x.com"}).status_code == 409)

# empréstimo e devolução
r = c.post("/api/emprestimos", headers=H, json={"livro_id": lid, "usuario_id": uid})
check("emprestar", r.status_code == 201 and r.json["situacao"] == "em_andamento"); eid = r.json["id"]
check("disponibilidade cai para 1", c.get(f"/api/livros/{lid}", headers=H).json["disponiveis"] == 1)
check("mesmo livro duas vezes -> 409", c.post("/api/emprestimos", headers=H, json={"livro_id": lid, "usuario_id": uid}).status_code == 409)
check("não exclui livro com histórico", c.delete(f"/api/livros/{lid}", headers=H).status_code == 409)
check("não reduz estoque abaixo do emprestado", c.put(f"/api/livros/{lid}", headers=H, json={**livro, "quantidade": 0}).status_code == 400)

# simula atraso de 4 dias
db = sqlite3.connect(os.environ["BIBLIOTECA_DB"])
db.execute("UPDATE emprestimos SET data_prevista = ? WHERE id = ?", ((date.today() - timedelta(days=4)).isoformat(), eid)); db.commit(); db.close()
check("aparece como atrasado", c.get("/api/emprestimos?status=atrasados", headers=H).json[0]["id"] == eid)
l2 = c.post("/api/livros", headers=H, json={"titulo": "Outro", "autor": "Autor", "quantidade": 1}).json["id"]
check("usuário atrasado não pega novo livro", c.post("/api/emprestimos", headers=H, json={"livro_id": l2, "usuario_id": uid}).status_code == 409)
r = c.post(f"/api/emprestimos/{eid}/devolucao", headers=H)
check("devolução com multa de 4 dias (R$ 2,00)", r.status_code == 200 and r.json["multa"] == 2.0 and r.json["situacao"] == "devolvido")
check("disponibilidade volta para 2", c.get(f"/api/livros/{lid}", headers=H).json["disponiveis"] == 2)
check("devolver duas vezes -> 409", c.post(f"/api/emprestimos/{eid}/devolucao", headers=H).status_code == 409)

# limite de 3 empréstimos
ids = [c.post("/api/livros", headers=H, json={"titulo": f"L{i}", "autor": "A", "quantidade": 1}).json["id"] for i in range(4)]
codes = [c.post("/api/emprestimos", headers=H, json={"livro_id": i, "usuario_id": uid}).status_code for i in ids]
check("limite de 3 empréstimos em aberto", codes == [201, 201, 201, 409])

# consulta ao acervo
check("acervo só disponíveis", all(x["disponiveis"] > 0 for x in c.get("/api/acervo?disponiveis=1", headers=H).json))
r = c.get("/api/resumo", headers=H).json
check("resumo", r["emprestimos_abertos"] == 3 and r["usuarios"] == 1)

# usuário com empréstimo aberto não pode ser inativado
check("não inativa com empréstimo aberto", c.put(f"/api/usuarios/{uid}", headers=H, json={"nome": "João Pereira", "cpf": "52998224725", "email": "joao@x.com", "ativo": False}).status_code == 409)

print(f"\n{ok} testes passaram.")
