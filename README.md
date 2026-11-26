# Sistema de Gerenciamento de Biblioteca

Implementação do artigo "Sistema de Gerenciamento de Biblioteca" (UNINASSAU – Parnaíba, disciplina Framework Back-end).

**Stack:** Vue.js 3 (front-end) · Flask (API REST) · SQLite (banco de dados) · JWT (autenticação de segurança do projeto)

## Comandos para execultar na sua máquina
```bash
pip install -r requirements.txt
python app.py
```
Abra http://127.0.0.1:5000 (precisa de internet, o vue que utilizamos precisa ser carregado pela CDN).

## Testes
```bash
python test_api.py
```

## Módulos (Quadro 1 do artigo)
| # | Módulo | Onde |
|---|--------|------|
| 01 | Cadastro de livros | aba Livros · `/api/livros` |
| 02 | Cadastro de usuários | aba Usuários · `/api/usuarios` |
| 03 | Empréstimos | aba Empréstimos · `POST /api/emprestimos` |
| 04 | Devoluções | `POST /api/emprestimos/<id>/devolucao` |
| 05 | Consulta ao acervo | aba Consulta ao acervo · `/api/acervo` |

## Regras de negócio
Prazo definido quando você fez o empréstimo · multa de R$ 0,50/dia de atraso · máximo 3 empréstimos abertos por cada pessoa que contrata o empréstimo do acervo · vai bloquear um novo empréstimo para quem tem atraso ·
estoque nunca fica abaixo do total emprestado · livros/usuários com histórico não são excluídos.

## Segurança
Senhas com hash · token JWT (8 h) · perfis admin/bibliotecário · SQL parametrizado · validação de CPF, ISBN, e-mail e demais campos ·
limite de tentativas de login · cabeçalhos HTTP de segurança. Para produção, use HTTPS e um servidor WSGI (ex.: gunicorn).
