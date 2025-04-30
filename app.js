const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Prevent caching
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// Middleware to set correct MIME type for CSS files
app.use((req, res, next) => {
  if (req.url.endsWith('.css')) {
    res.set('Content-Type', 'text/css');
  }
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Session setup
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: 'mongodb://localhost:27017/MyLibrary' }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// Debug middleware for form submissions
app.use((req, res, next) => {
  if (req.method === 'POST' && ['/account/update-profile', '/account/update-password'].includes(req.path)) {
    console.log(`Request to ${req.path}:`, {
      headers: req.headers,
      body: req.body
    });
  }
  next();
});

// Multer for profile and password forms
const formUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    // Allow no files, only form fields
    cb(null, false);
  }
}).none(); // Expect no files, only fields

// Middleware to fetch user and note
const fetchUserAndNote = async (req, res, next) => {
  if (req.session.userId) {
    try {
      req.user = await User.findById(req.session.userId);
      req.note = await Note.findOne({ user: req.session.userId });
    } catch (err) {
      console.error('Error fetching user or note:', err);
      req.user = null;
      req.note = null;
    }
  }
  next();
};

app.use(fetchUserAndNote);

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/MyLibrary', { 
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
  createdAt: { type: Date, default: Date.now },
  storageUsed: { type: Number, default: 0 },
  storageLimit: { type: Number, default: 1024 * 1024 * 500 },
  pinnedBooks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Book' }]
});

const bookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, required: true },
  fileName: { type: String, required: true },
  fileData: { type: Buffer, required: true },
  fileType: { type: String, required: true, enum: ['pdf'] },
  contentType: { type: String, required: true },
  thumbnail: { type: Buffer },
  thumbnailType: { type: String },
  description: { type: String },
  tags: [{ type: String }],
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  uploadDate: { type: Date, default: Date.now },
  fileSize: { type: Number, required: true },
  visibility: { 
    type: String, 
    enum: ['private', 'public', 'restricted'], 
    default: 'private' 
  },
  accessList: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  }],
  pinCount: { type: Number, default: 0 }
});

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

const sanitizeHtml = require('sanitize-html');

const noteSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, default: '' },
  updatedAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);
const Request = mongoose.model('Request', requestSchema);
const Note = mongoose.model('Note', noteSchema);

// Configure multer for file uploads (PDFs)
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['application/pdf'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed'), false);
    }
  },
  limits: { fileSize: 50 * 1024 * 1024 }
});

// Helper function to determine file type from MIME type
function getFileTypeFromMime(mimeType) {
  if (mimeType === 'application/pdf') return 'pdf';
  return null;
}

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
};

// Error handling middleware for multer
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).render('upload', { error: err.message, user: req.user, note: req.note ? req.note.content : '' });
  } else if (err) {
    return res.status(400).render('upload', { error: err.message, user: req.user, note: req.note ? req.note.content : '' });
  }
  next();
});

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.user, note: req.note ? req.note.content : '' });
});

app.get('/signup', (req, res) => {
  res.render('signup', { user: req.user, note: req.note ? req.note.content : '' });
});

app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).render('signup', { error: 'All fields are required', user: req.user, note: req.note ? req.note.content : '' });
    }
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).render('signup', { error: 'User already exists', user: req.user, note: req.note ? req.note.content : '' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });
    await newUser.save();
    // Create a note document for the new user
    const newNote = new Note({
      user: newUser._id,
      content: ''
    });
    await newNote.save();
    res.redirect('/login');
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).render('signup', { error: 'Server error', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { user: req.user, note: req.note ? req.note.content : '' });
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).render('login', { error: 'Email and password are required', user: req.user, note: req.note ? req.note.content : '' });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).render('login', { error: 'Invalid credentials', user: req.user, note: req.note ? req.note.content : '' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).render('login', { error: 'Invalid credentials', user: req.user, note: req.note ? req.note.content : '' });
    }
    req.session.userId = user._id;
    res.redirect('/library');
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).render('login', { error: 'Server error', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/library', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    const books = await Book.find({ uploadedBy: req.session.userId });
    res.render('library', { 
      books, 
      user,
      pinnedBooks: user.pinnedBooks,
      note: req.note ? req.note.content : ''
    });
  } catch (err) {
    console.error('Library error:', err);
    res.status(500).render('error', { message: 'Failed to load your library', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/pinned', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    await user.populate('pinnedBooks'); // Populate pinnedBooks
    res.render('pinned', { 
      pinnedBooks: user.pinnedBooks,
      user,
      note: req.note ? req.note.content : ''
    });
  } catch (err) {
    console.error('Pinned books error:', err);
    res.status(500).render('error', { message: 'Failed to load your pinned books', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.post('/book/:bookId/pin', isAuthenticated, async (req, res) => {
  try {
    const bookId = req.params.bookId;
    const user = await User.findById(req.session.userId);
    const book = await Book.findById(bookId);
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
    const isPinned = user.pinnedBooks.includes(bookId);
    if (isPinned) {
      user.pinnedBooks = user.pinnedBooks.filter(id => id.toString() !== bookId);
      book.pinCount = Math.max(0, book.pinCount - 1);
    } else {
      user.pinnedBooks.push(bookId);
      book.pinCount = (book.pinCount || 0) + 1;
    }
    await user.save();
    await book.save();
    res.json({ 
      success: true, 
      isPinned: !isPinned,
      pinCount: book.pinCount
    });
  } catch (err) {
    console.error('Pin/unpin error:', err);
    res.status(500).json({ success: false, message: 'Failed to update pin status' });
  }
});

app.get('/upload', isAuthenticated, (req, res) => {
  res.render('upload', { user: req.user, note: req.note ? req.note.content : '' });
});

app.post('/upload', isAuthenticated, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).render('upload', { error: 'Please upload a file', user: req.user, note: req.note ? req.note.content : '' });
    }
    const { title, author, visibility, description, tags } = req.body;
    const tagArray = tags ? tags.split(',').map(tag => tag.trim()) : [];
    if (!['private', 'public', 'restricted'].includes(visibility)) {
      return res.status(400).render('upload', { error: 'Invalid visibility option', user: req.user, note: req.note ? req.note.content : '' });
    }
    const user = await User.findById(req.session.userId);
    const fileSize = req.file.size;
    if (user.storageUsed + fileSize > user.storageLimit) {
      return res.status(400).render('upload', { 
        error: 'You have exceeded your storage limit. Please delete some files or upgrade your plan.',
        user: req.user,
        note: req.note ? req.note.content : ''
      });
    }
    const fileType = getFileTypeFromMime(req.file.mimetype);
    if (!fileType) {
      return res.status(400).render('upload', { error: 'Only PDF files are allowed', user: req.user, note: req.note ? req.note.content : '' });
    }
    const newBook = new Book({
      title,
      author,
      fileName: req.file.originalname,
      fileData: req.file.buffer,
      fileType: fileType,
      contentType: req.file.mimetype,
      description,
      tags: tagArray,
      uploadedBy: req.session.userId,
      visibility,
      fileSize
    });
    await newBook.save();
    user.storageUsed += fileSize;
    await user.save();
    res.redirect('/library');
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).render('upload', { error: 'Failed to upload file', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/view/:bookId', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findById(req.params.bookId);
    if (!book) {
      return res.status(400).render('error', { message: 'Book not found', user: req.user, note: req.note ? req.note.content : '' });
    }
    const isOwner = book.uploadedBy.toString() === req.session.userId;
    const hasAccess = book.accessList.includes(req.session.userId);
    const isPublic = book.visibility === 'public';
    if (!isOwner && !isPublic && !hasAccess) {
      return res.status(403).render('error', { message: 'You do not have access to this file', user: req.user, note: req.note ? req.note.content : '' });
    }
    res.render('pdf-viewer', { book, user: req.user, note: req.note ? req.note.content : '' });
  } catch (err) {
    console.error('View error:', err);
    res.status(500).render('error', { message: 'Failed to load file', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/file/:bookId', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findById(req.params.bookId);
    if (!book) {
      return res.status(404).send('File not found');
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
    res.send(book.fileData);
  } catch (err) {
    console.error('File fetch error:', err);
    res.status(500).send('Failed to load file');
  }
});

app.get('/thumbnail/:bookId', async (req, res) => {
  try {
    const book = await Book.findById(req.params.bookId);
    if (!book || !book.thumbnail) {
      return res.sendFile(path.join(__dirname, 'public', 'images', 'default-thumbnail.jpg'), (err) => {
        if (err) {
          console.error('Default thumbnail not found:', err);
          res.status(404).send('Default thumbnail not found');
        }
      });
    }
    res.set({
      'Content-Type': book.thumbnailType || 'image/jpeg',
      'Content-Disposition': `inline; filename="thumbnail-${book._id}.jpg"`
    });
    res.send(book.thumbnail);
  } catch (err) {
    console.error('Thumbnail fetch error:', err);
    res.status(500).send('Failed to load thumbnail');
  }
});

app.delete('/book/:id', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findOne({ _id: req.params.id, uploadedBy: req.session.userId });
    if (!book) {
      return res.status(400).json({ success: false, message: 'Book not found' });
    }
    const user = await User.findById(req.session.userId);
    user.storageUsed = Math.max(0, user.storageUsed - book.fileSize);
    await user.save();
    await User.updateMany(
      { pinnedBooks: book._id },
      { $pull: { pinnedBooks: book._id } }
    );
    await Book.deleteOne({ _id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    console.error('Book deletion error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

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

app.get('/explore', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    const publicBooks = await Book.find({
      visibility: 'public',
      uploadedBy: { $ne: req.session.userId }
    }).populate('uploadedBy', 'username');
    const accessibleBooks = await Book.find({
      visibility: 'restricted',
      accessList: req.session.userId,
      uploadedBy: { $ne: req.session.userId }
    }).populate('uploadedBy', 'username');
    const pendingRequests = await Request.find({
      requestedBy: req.session.userId,
      status: 'pending'
    }).select('book');
    const pendingBookIds = pendingRequests.map(req => req.book.toString());
    const trendingBooks = await Book.find({
      visibility: 'public',
      pinCount: { $gt: 0 }
    })
    .sort({ pinCount: -1 })
    .limit(5)
    .populate('uploadedBy', 'username');
    res.render('explore', { 
      books: [...publicBooks, ...accessibleBooks],
      trendingBooks,
      pendingBookIds,
      currentUser: req.session.userId,
      user,
      pinnedBooks: user.pinnedBooks.map(id => id.toString()),
      note: req.note ? req.note.content : ''
    });
  } catch (err) {
    console.error('Explore error:', err);
    res.status(500).render('error', { message: 'Failed to load public books', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/my-requests', isAuthenticated, async (req, res) => {
  try {
    const sentRequests = await Request.find({ requestedBy: req.session.userId })
      .populate('book', 'title author')
      .populate('bookOwner', 'username');
    res.render('my-requests', { requests: sentRequests, user: req.user, note: req.note ? req.note.content : '' });
  } catch (err) {
    console.error('My requests error:', err);
    res.status(500).render('error', { message: 'Failed to load requests', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/access-requests', isAuthenticated, async (req, res) => {
  try {
    const receivedRequests = await Request.find({ 
      bookOwner: req.session.userId,
      status: 'pending'
    })
      .populate('book', 'title author')
      .populate('requestedBy', 'username email');
    res.render('access-requests', { requests: receivedRequests, user: req.user, note: req.note ? req.note.content : '' });
  } catch (err) {
    console.error('Access requests error:', err);
    res.status(500).render('error', { message: 'Failed to load access requests', user: req.user, note: req.note ? req.note.content : '' });
  }
});

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

app.get('/account', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    const storageUsedMB = Math.round(user.storageUsed / (1024 * 1024) * 10) / 10;
    const storageLimitMB = Math.round(user.storageLimit / (1024 * 1024));
    const storagePercentage = Math.round((user.storageUsed / user.storageLimit) * 100);
    res.render('account', { 
      user, 
      storageUsedMB, 
      storageLimitMB, 
      storagePercentage,
      error: null,
      success: null,
      note: req.note ? req.note.content : ''
    });
  } catch (err) {
    console.error('Account settings error:', err);
    res.status(500).render('error', { message: 'Failed to load account settings', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/account/storage-info', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).select('storageUsed storageLimit');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const storageUsedMB = Math.round(user.storageUsed / (1024 * 1024) * 10) / 10;
    const storageLimitMB = Math.round(user.storageLimit / (1024 * 1024));
    const storagePercentage = Math.round((user.storageUsed / user.storageLimit) * 100);
    res.json({
      success: true,
      storageUsedMB,
      storageLimitMB,
      storagePercentage
    });
  } catch (err) {
    console.error('Storage info error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch storage information' });
  }
});

app.post('/account/update-profile', isAuthenticated, formUpload, async (req, res) => {
  try {
    console.log('Raw req.body:', req.body);
    const { username, email, currentPassword } = req.body;

    const errors = [];
    if (!username || username.trim() === '') errors.push('Username is required');
    if (!email || email.trim() === '') errors.push('Email is required');
    if (!currentPassword || currentPassword.trim() === '') errors.push('Current password is required');

    if (errors.length > 0) {
      console.log('Update profile: Validation errors', errors);
      if (req.xhr) {
        return res.status(400).json({ success: false, message: errors.join('; ') });
      }
      const user = await User.findById(req.session.userId);
      return res.status(400).render('account', {
        user,
        storageUsedMB: user.storageUsed / (1024 * 1024),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: Math.round((user.storageUsed / user.storageLimit) * 100),
        error: errors.join('; '),
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    const user = await User.findById(req.session.userId);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      console.log('Update profile: Incorrect current password');
      if (req.xhr) {
        return res.status(400).json({ success: false, message: 'Incorrect current password' });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: user.storageUsed / (1024 * 1024),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: Math.round((user.storageUsed / user.storageLimit) * 100),
        error: 'Incorrect current password',
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    const existingUser = await User.findOne({
      $or: [{ username }, { email }],
      _id: { $ne: user._id }
    });
    if (existingUser) {
      console.log('Update profile: Username or email already taken', { username, email });
      if (req.xhr) {
        return res.status(400).json({ success: false, message: 'Username or email already taken' });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: user.storageUsed / (1024 * 1024),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: Math.round((user.storageUsed / user.storageLimit) * 100),
        error: 'Username or email already taken',
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    user.username = username.trim();
    user.email = email.trim();
    await user.save();
    console.log('Update profile: Success', { username, email });
    if (req.xhr) {
      return res.json({ success: true, message: 'Profile updated successfully' });
    }
    return res.redirect('/account');
  } catch (err) {
    console.error('Update profile error:', err);
    if (req.xhr) {
      return res.status(500).json({ success: false, message: 'Server error' });
    }
    const user = await User.findById(req.session.userId);
    return res.status(500).render('account', {
      user,
      storageUsedMB: user.storageUsed / (1024 * 1024),
      storageLimitMB: user.storageLimit / (1024 * 1024),
      storagePercentage: Math.round((user.storageUsed / user.storageLimit) * 100),
      error: 'Server error',
      success: null,
      note: req.note ? req.note.content : ''
    });
  }
});

app.post('/account/update-password', isAuthenticated, formUpload, async (req, res) => {
  try {
    console.log('Raw req.body:', req.body);
    const { currentPassword, newPassword, confirmPassword } = req.body;

    // Validate fields
    const errors = [];
    if (!currentPassword || currentPassword.trim() === '') errors.push('Current password is required');
    if (!newPassword || newPassword.trim() === '') errors.push('New password is required');
    if (!confirmPassword || confirmPassword.trim() === '') errors.push('Confirm password is required');

    if (errors.length > 0) {
      console.log('Update password: Validation errors', errors);
      if (req.xhr) {
        return res.status(400).json({ success: false, message: errors.join('; ') });
      }
      const user = await User.findById(req.session.userId);
      return res.status(400).render('account', {
        user,
        storageUsedMB: user.storageUsed / (1024 * 1024),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: Math.round((user.storageUsed / user.storageLimit) * 100),
        error: errors.join('; '),
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    const user = await User.findById(req.session.userId);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      console.log('Update password: Incorrect current password');
      if (req.xhr) {
        return res.status(400).json({ success: false, message: 'Incorrect current password' });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: user.storageUsed / (1024 * 1024),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: Math.round((user.storageUsed / user.storageLimit) * 100),
        error: 'Incorrect current password',
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    if (newPassword !== confirmPassword) {
      console.log('Update password: New passwords do not match');
      if (req.xhr) {
        return res.status(400).json({ success: false, message: 'New passwords do not match' });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: user.storageUsed / (1024 * 1024),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: Math.round((user.storageUsed / user.storageLimit) * 100),
        error: 'New passwords do not match',
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    console.log('Update password: Success');
    if (req.xhr) {
      return res.json({ success: true, message: 'Password updated successfully' });
    }
    return res.redirect('/account');
  } catch (err) {
    console.error('Update password error:', err);
    if (req.xhr) {
      return res.status(500).json({ success: false, message: 'Server error' });
    }
    const user = await User.findById(req.session.userId);
    return res.status(500).render('account', {
      user,
      storageUsedMB: user.storageUsed / (1024 * 1024),
      storageLimitMB: user.storageLimit / (1024 * 1024),
      storagePercentage: Math.round((user.storageUsed / user.storageLimit) * 100),
      error: 'Server error',
      success: null,
      note: req.note ? req.note.content : ''
    });
  }
});

app.post('/account/delete', isAuthenticated, formUpload, async (req, res) => {
  try {
    const { password, confirmDelete } = req.body;
    console.log('Delete account: Received data', { password, confirmDelete });
    if (!password || !confirmDelete) {
      console.log('Delete account: Missing password or confirmation', { password, confirmDelete });
      if (req.xhr) {
        return res.status(400).json({ success: false, message: 'Password and confirmation are required' });
      }
      return res.status(400).render('account', {
        user: await User.findById(req.session.userId),
        storageUsedMB: 0,
        storageLimitMB: 500,
        storagePercentage: 0,
        error: 'Password and confirmation are required',
        success: null,
        note: req.note ? req.note.content : ''
      });
    }
    const user = await User.findById(req.session.userId);
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Delete account: Invalid password');
      if (req.xhr) {
        return res.status(400).json({ success: false, message: 'Invalid password' });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: user.storageUsed / (1024 * 1024),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: Math.round((user.storageUsed / user.storageLimit) * 100),
        error: 'Invalid password',
        success: null,
        note: req.note ? req.note.content : ''
      });
    }
    await Book.deleteMany({ uploadedBy: user._id });
    await Request.deleteMany({ $or: [{ requestedBy: user._id }, { bookOwner: user._id }] });
    await Book.updateMany(
      { accessList: user._id },
      { $pull: { accessList: user._id } }
    );
    await Note.deleteOne({ user: user._id }); // Clean up the note
    await User.deleteOne({ _id: user._id });
    console.log('Delete account: Success');
    req.session.destroy(() => {
      if (req.xhr) {
        return res.json({ success: true, message: 'Account deleted successfully', redirect: '/' });
      }
      return res.redirect('/');
    });
  } catch (err) {
    console.error('Delete account error:', err);
    if (req.xhr) {
      return res.status(500).json({ success: false, message: 'Server error' });
    }
    return res.status(500).render('account', {
      user: await User.findById(req.session.userId),
      storageUsedMB: 0,
      storageLimitMB: 500,
      storagePercentage: 0,
      error: 'Server error',
      success: null,
      note: req.note ? req.note.content : ''
    });
  }
});

const sanitizeHtml = require('sanitize-html');

app.post('/notes/save', isAuthenticated, async (req, res) => {
  try {
    const { content } = req.body;
    let note = await Note.findOne({ user: req.session.userId });
    const sanitizedContent = sanitizeHtml(content || '', {
      allowedTags: ['b', 'br'], // Allow only specific tags
      allowedAttributes: {}
    });
    if (!note) {
      note = new Note({
        user: req.session.userId,
        content: sanitizedContent
      });
    } else {
      note.content = sanitizedContent;
      note.updatedAt = Date.now();
    }
    await note.save();
    res.json({ success: true, message: 'Note saved successfully' });
  } catch (err) {
    console.error('Save note error:', err);
    res.status(500).json({ success: false, message: 'Failed to save note' });
  }
});

app.get('/explore/search', isAuthenticated, async (req, res) => {
  try {
    const { query } = req.query;
    const searchRegex = new RegExp(query, 'i');
    const publicBooks = await Book.find({
      visibility: 'public',
      uploadedBy: { $ne: req.session.userId },
      $or: [
        { title: searchRegex },
        { author: searchRegex },
        { tags: searchRegex }
      ]
    }).populate('uploadedBy', 'username');
    const accessibleBooks = await Book.find({
      visibility: 'restricted',
      accessList: req.session.userId,
      uploadedBy: { $ne: req.session.userId },
      $or: [
        { title: searchRegex },
        { author: searchRegex },
        { tags: searchRegex }
      ]
    }).populate('uploadedBy', 'username');
    const books = [...publicBooks, ...accessibleBooks];
    res.json({ books });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ success: false, message: 'Failed to search books' });
  }
});

app.get('/library/search', isAuthenticated, async (req, res) => {
  try {
    const { query } = req.query;
    const searchRegex = new RegExp(query, 'i');
    const userBooks = await Book.find({
      uploadedBy: req.session.userId,
      $or: [
        { title: searchRegex },
        { author: searchRegex },
        { tags: searchRegex }
      ]
    });
    res.json({ books: userBooks });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ success: false, message: 'Failed to search books' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});