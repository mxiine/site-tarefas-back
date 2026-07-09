const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// INTERMEDIÁRIO (MIDDLEWARE) DE AUTENTICAÇÃO

// Esta função serve para proteger as rotas. Ela lê o "crachá" (Token JWT) enviado pelo frontend.
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // O cabeçalho costuma vir no formato: "Bearer TOKEN_AQUI"
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ erro: 'Acesso negado. Token não fornecido.' });
    }

    try {
        const verificado = jwt.verify(token, process.env.JWT_SECRET);
        req.usuarioId = verificado.usuarioId; // Guarda o ID do utilizador na requisição para usarmos à frente
        next(); // Permite que a requisição continue para a rota
    } catch (err) {
        res.status(403).json({ erro: 'Token inválido ou expirado.' });
    }
}

// ROTAS DE AUTENTICAÇÃO

// 1. Rota de Registo (Criar Novo Utilizador)
app.post('/auth/cadastro', async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ erro: 'Por favor, preencha o e-mail e a senha.' });
    }

    try {
        // Verificar se o email já está registado
        const utilizadorExiste = await prisma.usuario.findUnique({ where: { email } });
        if (utilizadorExiste) {
            return res.status(400).json({ erro: 'Este email já está em uso.' });
        }

        // Encriptar a senha (gera um hash seguro)
        const salt = await bcrypt.genSalt(10);
        const senhaEncriptada = await bcrypt.hash(senha, salt);

        // Guardar no Supabase
        const novoUsuario = await prisma.usuario.create({
            data: {
                email,
                senha: senhaEncriptada
            }
        });

        res.status(201).json({ mensagem: 'Utilizador criado com sucesso!', usuarioId: novoUsuario.id });
    } catch (error) {
        console.error("🚨 ERRO GRAVE NO CADASTRO:", error); 
        res.status(500).json({ erro: 'Erro ao criar utilizador.' });
    }
});

// 2. Rota de Login
app.post('/auth/login', async (req, res) => {
    const { email, senha } = req.body;

    try {
        // Procurar o utilizador pelo email
        const usuario = await prisma.usuario.findUnique({ where: { email } });
        if (!usuario) {
            return res.status(400).json({ erro: 'E-mail ou senha incorretos.' });
        }

        // Verificar se a senha está correta
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha);
        if (!senhaCorreta) {
            return res.status(400).json({ erro: 'E-mail ou senha incorretos.' });
        }

        // Criar o token JWT (válido por 1 dia)
        const token = jwt.sign({ usuarioId: usuario.id }, process.env.JWT_SECRET, { expiresIn: '1d' });

        // Enviar o token para o frontend
        res.json({ token, mensagem: 'Login efetuado com sucesso!' });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao efetuar login.' });
    }
});

// ==========================================
// ROTAS DE TAREFAS (AGORA PROTEGIDAS!)
// ==========================================

// Rota para Listar Tarefas (Apenas as do utilizador logado)
app.get('/tarefas', verificarToken, async (req, res) => {
    try {
        const tarefasDoUsuario = await prisma.tarefa.findMany({
            where: { usuarioId: req.usuarioId }, // Filtra pelo ID do utilizador vindo do token!
            orderBy: { criadoEm: 'desc' }
        });
        res.json(tarefasDoUsuario);
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao procurar tarefas.' });
    }
});

// Rota para Criar Tarefa (Ligada ao utilizador logado)
app.post('/tarefas', verificarToken, async (req, res) => {
    const { titulo, descricao } = req.body;

    try {
        const novaTarefa = await prisma.tarefa.create({
            data: {
                titulo,
                descricao: descricao || "",
                usuarioId: req.usuarioId // Vincula a tarefa automaticamente ao dono do token!
            }
        });
        res.status(201).json(novaTarefa);
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao criar tarefa.' });
    }
});

// ==========================================
// ROTA PARA ATUALIZAR TAREFA (Marcar como concluída)
// ==========================================
app.patch('/tarefas/:id', verificarToken, async (req, res) => {
    const { id } = req.params; // Pega o ID da tarefa vindo da URL
    const { concluida } = req.body; // Espera receber true ou false no corpo da requisição

    try {
        // 1. Busca a tarefa no banco para verificar se ela existe
        const tarefa = await prisma.tarefa.findUnique({
            where: { id: parseInt(id) }
        });

        if (!tarefa) {
            return res.status(404).json({ erro: 'Tarefa não encontrada.' });
        }

        // 2. Segurança: Verifica se a tarefa realmente pertence ao usuário logado
        if (tarefa.usuarioId !== req.usuarioId) {
            return res.status(403).json({ erro: 'Acesso negado. Esta tarefa não é sua.' });
        }

        // 3. Atualiza o status da tarefa
        const tarefaAtualizada = await prisma.tarefa.update({
            where: { id: parseInt(id) },
            data: { concluida: concluida }
        });

        res.json({ mensagem: 'Tarefa atualizada com sucesso!', tarefa: tarefaAtualizada });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao atualizar tarefa.' });
    }
});

// ==========================================
// ROTA PARA EXCLUIR TAREFA
// ==========================================
app.delete('/tarefas/:id', verificarToken, async (req, res) => {
    const { id } = req.params; // Pega o ID da tarefa vindo da URL

    try {
        // 1. Busca a tarefa no banco
        const tarefa = await prisma.tarefa.findUnique({
            where: { id: parseInt(id) }
        });

        if (!tarefa) {
            return res.status(404).json({ erro: 'Tarefa não encontrada.' });
        }

        // 2. Segurança: Verifica se a tarefa pertence ao usuário logado
        if (tarefa.usuarioId !== req.usuarioId) {
            return res.status(403).json({ erro: 'Acesso negado. Você não pode excluir esta tarefa.' });
        }

        // 3. Exclui a tarefa
        await prisma.tarefa.delete({
            where: { id: parseInt(id) }
        });

        res.json({ mensagem: 'Tarefa excluída com sucesso!' });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao excluir tarefa.' });
    }
});

// Rota simples para testar se o servidor está vivo
app.get('/', (req, res) => {
    res.send('Servidor de Tarefas com Login ativo! 🚀');
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor a correr na porta ${PORT} e ligado à Nuvem!`);
});
