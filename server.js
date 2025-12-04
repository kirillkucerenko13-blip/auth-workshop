import 'dotenv/config';
import express from 'express';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

const SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

const users = [
    { id: 1, email: 'admin@example.com', password: 'admin123', role: 'admin' },
    { id: 2, email: 'user@example.com', password: 'user123', role: 'user' }
];

const auth = (req, res, next) => {
    const h = req.headers.authorization || '';
    const [t, tk] = h.split(' ');
    if (t !== 'Bearer' || !tk) return res.status(401).json({ error: 'Missing token' });
    try {
        req.user = jwt.verify(tk, SECRET);
        next();
    } catch { res.status(401).json({ error: 'Invalid token' }); }
};

const checkRole = (roles) => (req, res, next) => 
    roles.includes(req.user?.role) ? next() : res.status(403).json({ error: 'Forbidden' });

app.post('/login', (req, res) => {
    const { email, password } = req.body || {};
    const u = users.find(x => x.email === email && x.password === password);
    if (!u) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ sub: u.id, role: u.role }, SECRET, { expiresIn: '15m' });
    res.json({ access_token: token });
});

app.get('/profile', auth, (req, res) => res.json({ id: req.user.sub, role: req.user.role }));

app.delete('/users/:id', auth, checkRole(['admin']), (req, res) => 
    res.json({ message: `User ${req.params.id} deleted` }));

app.listen(PORT, () => console.log(`Running on port ${PORT}`));