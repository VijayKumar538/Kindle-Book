// Server-side code (Node.js with Express)
// app.js

const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/kindleClone', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Define schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const bookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, required: true },
  fileName: { type: String, required: true },
  filePath: { type: String, required: true },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  uploadDate: { type: Date, default: Date.now }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Session setup
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: 'mongodb://localhost:27017/kindleClone' }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed'));
    }
  },
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// Models
const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
};

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.session.userId });
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).render('signup', { error: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await newUser.save();
    res.redirect('/login');
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).render('signup', { error: 'Server error' });
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).render('login', { error: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).render('login', { error: 'Invalid credentials' });
    }
    
    // Set session
    req.session.userId = user._id;
    res.redirect('/library');
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).render('login', { error: 'Server error' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/library', isAuthenticated, async (req, res) => {
  try {
    const books = await Book.find({ uploadedBy: req.session.userId });
    res.render('library', { books });
  } catch (err) {
    console.error('Library error:', err);
    res.status(500).render('error', { message: 'Failed to load library' });
  }
});

app.get('/upload', isAuthenticated, (req, res) => {
  res.render('upload');
});

app.post('/upload', isAuthenticated, upload.single('book'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).render('upload', { error: 'Please upload a PDF file' });
    }
    
    const newBook = new Book({
      title: req.body.title,
      author: req.body.author,
      fileName: req.file.filename,
      filePath: req.file.path,
      uploadedBy: req.session.userId
    });
    
    await newBook.save();
    res.redirect('/library');
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).render('upload', { error: 'Failed to upload book' });
  }
});

app.get('/read/:bookId', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findOne({ _id: req.params.bookId, uploadedBy: req.session.userId });
    
    if (!book) {
      return res.status(404).render('error', { message: 'Book not found' });
    }
    
    res.render('reader', { book });
  } catch (err) {
    console.error('Reader error:', err);
    res.status(500).render('error', { message: 'Failed to load book' });
  }
});

app.get('/pdf/:bookId', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findOne({ _id: req.params.bookId, uploadedBy: req.session.userId });
    
    if (!book) {
      return res.status(404).send('Book not found');
    }
    
    res.sendFile(path.resolve(book.filePath));
  } catch (err) {
    console.error('PDF fetch error:', err);
    res.status(500).send('Failed to load PDF');
  }
});

app.delete('/book/:id', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findOne({ _id: req.params.id, uploadedBy: req.session.userId });
    
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
    
    // Delete file from storage
    fs.unlink(book.filePath, async (err) => {
      if (err) {
        console.error('File deletion error:', err);
      }
      
      // Delete book record from database
      await Book.deleteOne({ _id: req.params.id });
      res.json({ success: true });
    });
  } catch (err) {
    console.error('Book deletion error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
