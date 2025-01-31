const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'angelo12.1996',  // Cambia con la tua password MySQL
  database: 'login'
});

// Middleware per autenticare il token JWT
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Token mancante' });

  jwt.verify(token, 'segreto_super_sicuro', (err, user) => {
    if (err) return res.status(403).json({ message: 'Token non valido' });
    req.user = user;
    next();
  });
}

// Endpoint per ottenere i dati del profilo
app.get('/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;
  db.query('SELECT id, name, email FROM utenti WHERE id = ?', [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ message: 'Utente non trovato' });
    }
    res.json(results[0]);
  });
});

// Endpoint di registrazione
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Controlla se l'email esiste già
  db.query('SELECT * FROM utenti WHERE email = ?', [email], async (err, result) => {
    if (result.length > 0) {
      return res.status(400).json({ message: 'Email già registrata' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.query('INSERT INTO utenti (name, email, password) VALUES (?, ?, ?)', 
    [name, email, hashedPassword], (err, result) => {
      if (err) {
        return res.status(500).json({ message: 'Errore nel server' });
      }
      res.status(201).json({ message: 'Registrazione avvenuta con successo' });
    });
  });
});

// Endpoint di login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM utenti WHERE email = ?', [email], async (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Errore nel server' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Credenziali errate' });
    }

    const isValidPassword = await bcrypt.compare(password, results[0].password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenziali errate' });
    }

    const token = jwt.sign({ id: results[0].id }, 'segreto_super_sicuro', { expiresIn: '1h' });

    res.json({
      message: 'Login effettuato con successo',
      token,
      user: {
        id: results[0].id,
        name: results[0].name,
        email: results[0].email
      }
    });
  });
});

db.connect(err => {
  if (err) {
    console.error('Errore di connessione al database:', err);
    return;
  }
  console.log('Connesso al database MySQL');
});

app.listen(3000, () => {
  console.log('Server in ascolto sulla porta 3000');
});
