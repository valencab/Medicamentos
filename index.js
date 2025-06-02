
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

// Conectar a MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Conectado a MongoDB Atlas'))
  .catch(err => console.log('Error conectando a MongoDB:', err));

// Esquemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['usuario', 'admin'], default: 'usuario' },
  createdAt: { type: Date, default: Date.now }
});

const medicamentoSchema = new mongoose.Schema({
  nombre: { type: String, required: true },
  descripcion: { type: String, required: true },
  precio: { type: Number, required: true },
  stock: { type: Number, required: true },
  laboratorio: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Medicamento = mongoose.model('Medicamento', medicamentoSchema);

// Middleware de autenticación
const requireAuth = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
};

const requireAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.role === 'admin') {
    next();
  } else {
    res.status(403).send('Acceso denegado. Solo administradores.');
  }
};

// Rutas principales
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/login', (req, res) => {
  res.render('login', { error: null, user: req.session.user });
});

app.get('/register', (req, res) => {
  res.render('register', { error: null, user: req.session.user });
});

// Autenticación
app.post('/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.render('register', { error: 'El usuario ya existe', user: req.session.user });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      password: hashedPassword,
      role: role || 'usuario'
    });
    
    await user.save();
    res.redirect('/login');
  } catch (error) {
    res.render('register', { error: 'Error al registrar usuario', user: req.session.user });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.render('login', { error: 'Usuario no encontrado', user: req.session.user });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.render('login', { error: 'Contraseña incorrecta', user: req.session.user });
    }
    
    req.session.user = {
      id: user._id,
      username: user.username,
      role: user.role
    };
    
    res.redirect('/medicamentos');
  } catch (error) {
    res.render('login', { error: 'Error al iniciar sesión', user: req.session.user });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Rutas de medicamentos
app.get('/medicamentos', requireAuth, async (req, res) => {
  try {
    const medicamentos = await Medicamento.find().sort({ createdAt: -1 });
    res.render('medicamentos', { 
      medicamentos, 
      user: req.session.user 
    });
  } catch (error) {
    res.status(500).send('Error al obtener medicamentos');
  }
});

app.get('/admin', requireAdmin, async (req, res) => {
  try {
    const medicamentos = await Medicamento.find().sort({ createdAt: -1 });
    res.render('admin', { 
      medicamentos, 
      user: req.session.user 
    });
  } catch (error) {
    res.status(500).send('Error al cargar panel de administración');
  }
});

// CRUD de medicamentos (solo admin)
app.post('/medicamentos', requireAdmin, async (req, res) => {
  try {
    const { nombre, descripcion, precio, stock, laboratorio } = req.body;
    const medicamento = new Medicamento({
      nombre,
      descripcion,
      precio: parseFloat(precio),
      stock: parseInt(stock),
      laboratorio
    });
    
    await medicamento.save();
    res.redirect('/admin');
  } catch (error) {
    res.status(500).send('Error al agregar medicamento');
  }
});

app.post('/medicamentos/:id/delete', requireAdmin, async (req, res) => {
  try {
    await Medicamento.findByIdAndDelete(req.params.id);
    res.redirect('/admin');
  } catch (error) {
    res.status(500).send('Error al eliminar medicamento');
  }
});

app.post('/medicamentos/:id/edit', requireAdmin, async (req, res) => {
  try {
    const { nombre, descripcion, precio, stock, laboratorio } = req.body;
    await Medicamento.findByIdAndUpdate(req.params.id, {
      nombre,
      descripcion,
      precio: parseFloat(precio),
      stock: parseInt(stock),
      laboratorio
    });
    res.redirect('/admin');
  } catch (error) {
    res.status(500).send('Error al actualizar medicamento');
  }
});

// API endpoints
app.get('/api/medicamentos', requireAuth, async (req, res) => {
  try {
    const medicamentos = await Medicamento.find();
    res.json(medicamentos);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener medicamentos' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
