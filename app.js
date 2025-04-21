const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect('mongodb+srv://vijaykumar1998kv:SehCGpSwG79J2ImU@mylibrary.u6qqrud.mongodb.net/MyLibrary?retryWrites=true&w=majority&appName=MyLibrary', { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

// Define schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

// Updated Book schema to store PDF as binary data
const bookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, required: true },
  fileName: { type: String, required: true },
  pdfData: { type: Buffer, required: true }, // Store PDF as binary
  contentType: { type: String, required: true, default: 'application/pdf' },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  uploadDate: { type: Date, default: Date.now },
  visibility: { 
    type: String, 
    enum: ['private', 'public', 'restricted'], 
    default: 'private' 
  },
  accessList: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  }]
});

// Request schema
const requestSchema = new mongoose.Schema({
  book: { type: mongoose.Schema.Types.ObjectId, ref: 'Book', required: true },
  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  bookOwner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'declined'], 
    default: 'pending' 
  },
  requestDate: { type: Date, default: Date.now },
  responseDate: { type: Date }
});

// Models
const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);
const Request = mongoose.model('Request', requestSchema);

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
  store: MongoStore.create({ mongoUrl: 'mongodb+srv://vijaykumar1998kv:SehCGpSwG79J2ImU@mylibrary.u6qqrud.mongodb.net/MyLibrary?retryWrites=true&w=majority&appName=MyLibrary' }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// Configure multer for memory storage (no disk storage)
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed'));
    }
  },
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

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
    
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).render('signup', { error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
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
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).render('login', { error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).render('login', { error: 'Invalid credentials' });
    }
    
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
    const booksWithAccessCount = await Promise.all(books.map(async (book) => {
      const accessCount = book.accessList.length;
      return {
        ...book.toObject(),
        accessCount
      };
    }));
    
    res.render('library', { books: booksWithAccessCount });
  } catch (err) {
    console.error('Library error:', err);
    res.status(500).render('error', { message: 'Failed to load your library' });
  }
});

app.get('/upload', isAuthenticated, (req, res) => {
  res.render('upload');
});

// Updated upload route to store PDF in MongoDB
app.post('/upload', isAuthenticated, upload.single('book'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).render('upload', { error: 'Please upload a PDF file' });
    }
    
    const { title, author, visibility } = req.body;
    
    if (!['private', 'public', 'restricted'].includes(visibility)) {
      return res.status(400).render('upload', { error: 'Invalid visibility option' });
    }
    
    const newBook = new Book({
      title,
      author,
      fileName: req.file.originalname,
      pdfData: req.file.buffer, // Store PDF as Buffer
      uploadedBy: req.session.userId,
      visibility
    });
    
    await newBook.save();
    res.redirect('/library');
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).render('upload', { error: 'Failed to upload book' });
  }
});

// Updated read route
app.get('/read/:bookId', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findById(req.params.bookId);
    
    if (!book) {
      return res.status(404).render('error', { message: 'Book not found' });
    }
    
    const isOwner = book.uploadedBy.toString() === req.session.userId;
    const hasAccess = book.accessList.includes(req.session.userId);
    const isPublic = book.visibility === 'public';
    
    if (!isOwner && !isPublic && !hasAccess) {
      return res.status(403).render('error', { message: 'You do not have access to this book' });
    }
    
    res.render('reader', { book });
  } catch (err) {
    console.error('Reader error:', err);
    res.status(500).render('error', { message: 'Failed to load book' });
  }
});

// Updated PDF fetch route to read from MongoDB
app.get('/pdf/:bookId', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findById(req.params.bookId);
    
    if (!book) {
      return res.status(404).send('Book not found');
    }
    
    const isOwner = book.uploadedBy.toString() === req.session.userId;
    const hasAccess = book.accessList.includes(req.session.userId);
    const isPublic = book.visibility === 'public';
    
    if (!isOwner && !isPublic && !hasAccess) {
      return res.status(403).send('Access denied');
    }
    
    res.set({
      'Content-Type': book.contentType,
      'Content-Disposition': `inline; filename="${book.fileName}"`
    });
    res.send(book.pdfData);
  } catch (err) {
    console.error('PDF fetch error:', err);
    res.status(500).send('Failed to load PDF');
  }
});

// Updated delete route (no file system operation)
app.delete('/book/:id', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findOne({ _id: req.params.id, uploadedBy: req.session.userId });
    
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
    
    await Book.deleteOne({ _id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    console.error('Book deletion error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Update book visibility
app.put('/book/:bookId/visibility', isAuthenticated, async (req, res) => {
  try {
    const { visibility } = req.body;
    
    if (!['private', 'public', 'restricted'].includes(visibility)) {
      return res.status(400).json({ success: false, message: 'Invalid visibility option' });
    }
    
    const book = await Book.findById(req.params.bookId);
    
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
    
    if (book.uploadedBy.toString() !== req.session.userId) {
      return res.status(403).json({ success: false, message: 'You do not own this book' });
    }
    
    book.visibility = visibility;
    if (visibility !== 'restricted') {
      book.accessList = [];
    }
    
    await book.save();
    res.json({ success: true, message: 'Visibility updated successfully' });
  } catch (err) {
    console.error('Update visibility error:', err);
    res.status(500).json({ success: false, message: 'Failed to update visibility' });
  }
});

// Get users with access to a book
app.get('/book/:bookId/access-list', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findById(req.params.bookId);
    
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
    
    if (book.uploadedBy.toString() !== req.session.userId) {
      return res.status(403).json({ success: false, message: 'You do not own this book' });
    }
    
    const users = await User.find({
      _id: { $in: book.accessList }
    }).select('username email');
    
    res.json({ success: true, users });
  } catch (err) {
    console.error('Get access list error:', err);
    res.status(500).json({ success: false, message: 'Failed to get access list' });
  }
});

// Remove user access
app.delete('/book/:bookId/access/:userId', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findById(req.params.bookId);
    
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
    
    if (book.uploadedBy.toString() !== req.session.userId) {
      return res.status(403).json({ success: false, message: 'You do not own this book' });
    }
    
    const userIndex = book.accessList.indexOf(req.params.userId);
    
    if (userIndex !== -1) {
      book.accessList.splice(userIndex, 1);
      await book.save();
    }
    
    res.json({ success: true, message: 'Access removed successfully' });
  } catch (err) {
    console.error('Remove access error:', err);
    res.status(500).json({ success: false, message: 'Failed to remove access' });
  }
});

// Explore public books
app.get('/explore', isAuthenticated, async (req, res) => {
  try {
    const publicBooks = await Book.find({
      visibility: 'public',
      uploadedBy: { $ne: req.session.userId }
    }).populate('uploadedBy', 'username');
    
    const accessibleBooks = await Book.find({
      visibility: 'restricted',
      accessList: req.session.userId,
      uploadedBy: { $ne: req.session.userId }
    }).populate('uploadedBy', 'username');
    
    const restrictedBooks = await Book.find({
      visibility: 'restricted',
      accessList: { $ne: req.session.userId },
      uploadedBy: { $ne: req.session.userId }
    }).populate('uploadedBy', 'username');
    
    const books = [...publicBooks, ...accessibleBooks, ...restrictedBooks];
    
    const pendingRequests = await Request.find({
      requestedBy: req.session.userId,
      status: 'pending'
    }).select('book');
    
    const pendingBookIds = pendingRequests.map(req => req.book.toString());
    
    res.render('explore', { 
      books, 
      pendingBookIds,
      currentUser: req.session.userId
    });
  } catch (err) {
    console.error('Explore error:', err);
    res.status(500).render('error', { message: 'Failed to load public books' });
  }
});

// Show all requests
app.get('/my-requests', isAuthenticated, async (req, res) => {
  try {
    const sentRequests = await Request.find({ requestedBy: req.session.userId })
      .populate('book', 'title author')
      .populate('bookOwner', 'username');
    
    res.render('my-requests', { requests: sentRequests });
  } catch (err) {
    console.error('My requests error:', err);
    res.status(500).render('error', { message: 'Failed to load requests' });
  }
});

// Access requests management page
app.get('/access-requests', isAuthenticated, async (req, res) => {
  try {
    const receivedRequests = await Request.find({ 
      bookOwner: req.session.userId,
      status: 'pending'
    })
      .populate('book', 'title author')
      .populate('requestedBy', 'username email');
    
    res.render('access-requests', { requests: receivedRequests });
  } catch (err) {
    console.error('Access requests error:', err);
    res.status(500).render('error', { message: 'Failed to load access requests' });
  }
});

// Request access to a book
app.post('/request-access/:bookId', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findById(req.params.bookId);
    
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
    
    const existingRequest = await Request.findOne({
      book: book._id,
      requestedBy: req.session.userId,
      status: 'pending'
    });
    
    if (existingRequest) {
      return res.json({ success: false, message: 'Access request already sent' });
    }
    
    const request = new Request({
      book: book._id,
      requestedBy: req.session.userId,
      bookOwner: book.uploadedBy
    });
    
    await request.save();
    res.json({ success: true, message: 'Access request sent successfully' });
  } catch (err) {
    console.error('Request access error:', err);
    res.status(500).json({ success: false, message: 'Failed to send request' });
  }
});

// Handle access request (approve/decline)
app.post('/handle-request/:requestId', isAuthenticated, async (req, res) => {
  try {
    const { action } = req.body;
    
    if (!['approve', 'decline'].includes(action)) {
      return res.status(400).json({ success: false, message: 'Invalid action' });
    }
    
    const request = await Request.findById(req.params.requestId)
      .populate('book');
    
    if (!request) {
      return res.status(404).json({ success: false, message: 'Request not found' });
    }
    
    if (request.bookOwner.toString() !== req.session.userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    
    request.status = action === 'approve' ? 'approved' : 'declined';
    request.responseDate = new Date();
    await request.save();
    
    if (action === 'approve') {
      const book = await Book.findById(request.book._id);
      if (!book.accessList.includes(request.requestedBy)) {
        book.accessList.push(request.requestedBy);
        await book.save();
      }
    }
    
    res.json({ success: true, message: `Request ${action}d successfully` });
  } catch (err) {
    console.error('Handle request error:', err);
    res.status(500).json({ success: false, message: 'Failed to process request' });
  }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
