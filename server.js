require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');


const app = express();
app.use(cors());
// Middleware para processar JSON
app.use(express.json());

/**
 * Rota de login:
 * - Recebe "username" e "password" via JSON.
 * - Se as credenciais baterem com as definidas no .env, gera um token JWT com validade de 1 hora.
 * - Retorna o token na resposta JSON.
 */
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASSWORD) {
    // Cria o payload do token
    const payload = { username };
    // Gera o token JWT com expiração de 1 hora
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    return res.status(200).json({ message: 'Login efetuado com sucesso', token });
  }
  
  return res.status(401).json({ message: 'Credenciais inválidas' });
});

/**
 * Middleware para autenticação:
 * - Verifica o token JWT enviado no header Authorization.
 * - O header deve ter o formato: "Bearer <token>".
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Token não fornecido' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(401).json({ message: 'Token inválido ou expirado' });
    }
    req.user = user;
    next();
  });
}

/**
 * Rota protegida para a área administrativa:
 * - Somente acessível se um token válido for enviado.
 */
app.get('/admin', authenticateToken, (req, res) => {
  res.status(200).json({ message: 'Bem-vindo à área administrativa', user: req.user });
});

// Inicializa o servidor na porta definida no .env ou 3000 por padrão
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
