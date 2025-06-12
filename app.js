const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const sanitizeHtml = require('sanitize-html');
const http = require('http');
const socketIo = require('socket.io');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
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

// Session setup with shorter expiration (30 minutes)
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes in milliseconds
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: 'mongodb://localhost:27017/' }),
  cookie: { 
    maxAge: SESSION_TIMEOUT,
    secure: false, // Set to true if using HTTPS
    httpOnly: true
  }
}));

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

// Passport Google Strategy
passport.use(new GoogleStrategy({
  clientID: '660588293356-lhtl1spq2eocqeaj6agg4ub0qttoh044.apps.googleusercontent.com', // Replace with your Google Client ID
  clientSecret: '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', // Replace with your Google Client Secret
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (user) {
      return done(null, user);
    }
    // Check if email already exists (for users who signed up manually)
    user = await User.findOne({ email: profile.emails[0].value });
    if (user) {
      // Link Google account to existing user
      user.googleId = profile.id;
      await user.save();
      return done(null, user);
    }
    // Create new user
    user = new User({
      googleId: profile.id,
      username: profile.displayName.replace(/\s/g, '').toLowerCase(),
      email: profile.emails[0].value,
      profession: 'BookHive', // Default profession; prompt user to update later
      password: await bcrypt.hash(Math.random().toString(36).slice(-8), 10) // Random password for Google users
    });
    await user.save();
    const newNote = new Note({
      user: user._id,
      content: ''
    });
    await newNote.save();
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Middleware to check session timeout
app.use((req, res, next) => {
  if (req.session.userId) {
    const now = Date.now();
    const lastActivity = req.session.lastActivity || now;
    
    if (now - lastActivity > SESSION_TIMEOUT) {
      req.session.destroy(() => {
        res.clearCookie('connect.sid');
        return res.redirect('/login');
      });
    } else {
      req.session.lastActivity = now;
      next();
    }
  } else {
    next();
  }
});

// Debug middleware for form submissions
app.use((req, res, next) => {
  if (req.method === 'POST' && ['/account/update-profile', '/account/update-password', '/feedback', '/account/delete', '/request-access'].includes(req.path)) {
    console.log(`Request to ${req.path}:`, {
      headers: req.headers,
      body: req.body,
      session: req.session
    });
    const originalJson = res.json;
    const originalRender = res.render;
    const originalRedirect = res.redirect;
    res.json = function (data) {
      console.log(`Response to ${req.path}: JSON`, data);
      return originalJson.apply(res, arguments);
    };
    res.render = function (view, locals) {
      console.log(`Response to ${req.path}: Render view=${view}`, locals);
      return originalRender.apply(res, arguments);
    };
    res.redirect = function (url) {
      console.log(`Response to ${req.path}: Redirect to ${url}`);
      return originalRedirect.apply(res, arguments);
    };
  }
  next();
});

// Multer for profile and password forms
const formUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    cb(null, false);
  }
}).none();

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
mongoose.connect('mongodb://localhost:27017/', { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
}).then(async () => {
  console.log('Connected to MongoDB');
  try {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const adminUser = new User({
        username: 'admin',
        email: 'admin@bookhive.com',
        password: hashedPassword,
        profession: 'BookHive',
        isAdmin: true
      });
      await adminUser.save();
      console.log('Admin user created: username=admin, password=admin123');
      const adminNote = new Note({
        user: adminUser._id,
        content: 'Admin notes'
      });
      await adminNote.save();
    }
  } catch (err) {
    console.error('Error creating admin user:', err);
  }
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// Define schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String }, // Not required for Google users
  googleId: { type: String, unique: true, sparse: true },
  profession: { 
    type: String, 
    required: true, 
    enum: ['BookHive'] 
  },
  createdAt: { type: Date, default: Date.now },
  storageUsed: { type: Number, default: 0 },
  storageLimit: { type: Number, default: 1024 * 1024 * 500 },
  pinnedBooks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Book' }],
  isAdmin: { type: Boolean, default: false }
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

const noteSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, default: '' },
  updatedAt: { type: Date, default: Date.now }
});

const feedbackSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  submittedAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  profession: { type: String, required: true, enum: ['BookHive'] },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const newsSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  image: { type: Buffer },
  imageType: { type: String },
  createdAt: { type: Date, default: Date.now },
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

// Models
const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);
const Request = mongoose.model('Request', requestSchema);
const Note = mongoose.model('Note', noteSchema);
const Feedback = mongoose.model('Feedback', feedbackSchema);
const Message = mongoose.model('Message', messageSchema);
const News = mongoose.model('News', newsSchema);

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

const newsImageUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPEG and PNG images are allowed'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

// Helper function to determine file type from MIME type
function getFileTypeFromMime(mimeType) {
  if (mimeType === 'application/pdf') return 'pdf';
  return null;
}

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.userId || req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

// Admin authentication middleware
const isAdmin = async (req, res, next) => {
  if (!req.session.userId && !req.isAuthenticated()) {
    return res.redirect('/login');
  }
  const user = req.user || await User.findById(req.session.userId);
  if (!user || !user.isAdmin) {
    return res.status(403).render('error', { message: 'Admin access required', user: req.user, note: req.note ? req.note.content : '' });
  }
  req.user = user;
  next();
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

// Socket.IO setup for profession-based chat and notifications
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('joinProfession', async ({ userId, profession }) => {
    socket.join(profession);
    socket.join(userId.toString()); // Join user-specific room for notifications
    console.log(`User ${userId} joined ${profession} chat and user room ${userId}`);
    
    const messages = await Message.find({ profession })
      .sort({ timestamp: -1 })
      .limit(50)
      .populate('user', 'username');
    socket.emit('chatHistory', messages.reverse());
  });

  socket.on('chatMessage', async ({ userId, profession, content }) => {
    if (!content || content.trim() === '') return;
    
    const sanitizedContent = sanitizeHtml(content, {
      allowedTags: [],
      allowedAttributes: {}
    });

    const message = new Message({
      user: userId,
      profession,
      content: sanitizedContent
    });
    await message.save();

    const populatedMessage = await Message.findById(message._id).populate('user', 'username');
    io.to(profession).emit('chatMessage', populatedMessage);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Google Auth Routes
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

app.get('/auth/google/callback', passport.authenticate('google', {
  failureRedirect: '/login'
}), (req, res) => {
  req.session.userId = req.user._id;
  req.session.lastActivity = Date.now();
  if (req.user.isAdmin) {
    res.redirect('/admin');
  } else if (!req.user.profession) {
    res.redirect('/account'); // Prompt to update profession
  } else {
    res.redirect('/library');
  }
});

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.user, note: req.note ? req.note.content : '' });
});

app.get('/signup', (req, res) => {
  res.render('signup', { user: req.user, note: req.note ? req.note.content : '', error: null });
});

app.post('/signup', async (req, res) => {
  try {
    const { username, email, password, profession } = req.body;
    if (!username || !email || !password || !profession) {
      return res.status(400).render('signup', { error: 'All fields are required', user: req.user, note: req.note ? req.note.content : '' });
    }
    if (!['BookHive'].includes(profession)) {
      return res.status(400).render('signup', { error: 'Invalid profession selected', user: req.user, note: req.note ? req.note.content : '' });
    }
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).render('signup', { error: 'User already exists', user: req.user, note: req.note ? req.note.content : '' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      profession
    });
    await newUser.save();
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
  res.render('login', { error: null, user: req.user, note: req.note ? req.note.content : '' });
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
    req.session.lastActivity = Date.now();
    if (user.isAdmin) {
      res.redirect('/admin');
    } else {
      res.redirect('/library');
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).render('login', { error: 'Server error', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).send('Failed to logout');
    }
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

app.get('/library', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
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
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
    await user.populate('pinnedBooks');
    res.render('pinned', {
      pinnedBooks: user.pinnedBooks,
      user,
      note: req.note ? req.note.content : ''
    });
  } catch (err) {
    console.error('Pinned books error:', err);
    res.status(500).render('error', { message: 'Failed to load pinned books', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.post('/book/:bookId/pin', isAuthenticated, async (req, res) => {
  try {
    const bookId = req.params.bookId;
    const user = await User.findById(req.session.userId);
    if (!user) {
      console.error(`User not found for ID: ${req.session.userId}`);
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot pin books' });
    }
    const book = await Book.findById(bookId);
    if (!book) {
      console.error(`Book not found for ID: ${bookId}`);
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
    console.log(`Pin updated: bookId=${bookId}, isPinned=${!isPinned}, pinCount=${book.pinCount}`);
    res.json({
      success: true,
      isPinned: !isPinned,
      pinCount: book.pinCount
    });
  } catch (err) {
    console.error(`Pin/unpin error for bookId=${req.params.bookId}:`, err);
    res.status(500).json({ success: false, message: 'Failed to update pin status' });
  }
});

app.get('/upload', isAuthenticated, (req, res) => {
  const user = req.user;
  if (user.isAdmin) {
    return res.redirect('/admin');
  }
  res.render('upload', { user: req.user, note: req.note ? req.note.content : '' });
});

app.post('/upload', isAuthenticated, upload.single('file'), async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
    if (!req.file) {
      return res.status(400).render('upload', { error: 'Please upload a file', user: req.user, note: req.note ? req.note.content : '' });
    }
    const { title, author, visibility, description, tags } = req.body;
    const tagArray = tags ? tags.split(',').map(tag => tag.trim()) : [];
    if (!['private', 'public', 'restricted'].includes(visibility)) {
      return res.status(400).render('upload', { error: 'Invalid visibility option', user: req.user, note: req.note ? req.note.content : '' });
    }
    const fileSize = req.file.size;
    if (user.storageUsed + fileSize > user.storageLimit) {
      return res.status(400).render('upload', {
        error: 'Storage limit exceeded. Delete some files or upgrade your plan.',
        user: req.user,
        note: req.note ? req.note.content : ''
      });
    }
    const fileType = getFileTypeFromMime(req.file.mimetype);
    if (!fileType) {
      return res.status(400).render('upload', { error: 'Only PDF files allowed', user: req.user, note: req.note ? req.note.content : '' });
    }
    const newBook = new Book({
      title,
      author,
      fileName: req.file.originalname,
      fileData: req.file.buffer,
      fileType,
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
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
    const book = await Book.findById(req.params.bookId);
    if (!book) {
      return res.status(404).render('error', { message: 'Book not found', user: req.user, note: req.note ? req.note.content : '' });
    }
    const isOwner = book.uploadedBy.toString() === req.session.userId;
    const hasAccess = book.accessList.includes(req.session.userId);
    const isPublic = book.visibility === 'public';
    if (!isOwner && !isPublic && !hasAccess) {
      return res.status(403).render('error', { message: 'Access denied', user: req.user, note: req.note ? req.note.content : '' });
    }
    res.render('pdf-viewer', { book, user: req.user, note: req.note ? req.note.content : '' });
  } catch (err) {
    console.error('View error:', err);
    res.status(500).render('error', { message: 'Failed to load file', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/file/:bookId', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).send('Admins cannot access this route');
    }
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
          console.error('Default thumbnail error:', err);
          res.status(404).send('Thumbnail not found');
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
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot delete books' });
    }
    const book = await Book.findOne({ _id: req.params.id, uploadedBy: req.session.userId });
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
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
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot modify book visibility' });
    }
    const { visibility } = req.body;
    if (!['private', 'public', 'restricted'].includes(visibility)) {
      return res.status(400).json({ success: false, message: 'Invalid visibility' });
    }
    const book = await Book.findById(req.params.bookId);
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
    if (book.uploadedBy.toString() !== req.session.userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    book.visibility = visibility;
    if (visibility !== 'restricted') {
      book.accessList = [];
    }
    await book.save();
    res.json({ success: true });
  } catch (err) {
    console.error('Visibility update error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/book/:bookId/access-list', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot access this route' });
    }
    const book = await Book.findById(req.params.bookId);
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
    if (book.uploadedBy.toString() !== req.session.userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    const users = await User.find({ _id: { $in: book.accessList } }).select('username email');
    res.json({ success: true, users });
  } catch (err) {
    console.error('Access list error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/book/:bookId/access/:userId', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot access this route' });
    }
    const book = await Book.findById(req.params.bookId);
    if (!book) {
      return res.status(404).json({ success: false, message: 'Book not found' });
    }
    if (book.uploadedBy.toString() !== req.session.userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    book.accessList = book.accessList.filter(id => id.toString() !== req.params.userId);
    await book.save();
    res.json({ success: true });
  } catch (err) {
    console.error('Remove access error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/explore', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
    const publicBooks = await Book.find({
      visibility: 'public',
      uploadedBy: { $ne: req.session.userId }
    }).populate('uploadedBy', 'username');
    const restrictedBooks = await Book.find({
      visibility: 'restricted',
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
      books: [...publicBooks, ...restrictedBooks],
      trendingBooks,
      pendingBookIds,
      currentUser: req.session.userId,
      user,
      pinnedBooks: user.pinnedBooks.map(id => id.toString()),
      note: req.note ? req.note.content : ''
    });
  } catch (err) {
    console.error('Explore error:', err);
    res.status(500).render('error', { message: 'Failed to load explore page', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/my-requests', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
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
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
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

app.post('/handle-request/:requestId', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot handle requests' });
    }
    const { action } = req.body;
    if (!['approve', 'decline'].includes(action)) {
      return res.status(400).json({ success: false, message: 'Invalid action' });
    }
    const request = await Request.findById(req.params.requestId).populate('book');
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
    res.json({ success: true, message: `Request ${action}d` });
  } catch (err) {
    console.error('Handle request error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/account', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
    const storageUsedMB = (user.storageUsed / (1024 * 1024)).toFixed(1);
    const storageLimitMB = user.storageLimit / (1024 * 1024);
    const storagePercentage = ((user.storageUsed / user.storageLimit) * 100).toFixed(0);
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
    console.error('Account error:', err);
    res.status(500).render('error', { message: 'Failed to load account', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/account/storage-info', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot access this route' });
    }
    const storageUsedMB = (user.storageUsed / (1024 * 1024)).toFixed(1);
    const storageLimitMB = user.storageLimit / (1024 * 1024);
    const storagePercentage = ((user.storageUsed / user.storageLimit) * 100).toFixed(0);
    res.json({
      success: true,
      storageUsedMB,
      storageLimitMB,
      storagePercentage
    });
  } catch (err) {
    console.error('Storage info error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/account/update-profile', isAuthenticated, formUpload, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
    const { username, email, currentPassword, profession } = req.body;
    const isAjax = req.get('X-Requested-With') === 'XMLHttpRequest';

    if (!username || !email || (!user.googleId && !currentPassword) || !profession) {
      const errorMsg = 'All fields required';
      if (isAjax) {
        return res.status(400).json({ success: false, message: errorMsg });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: (user.storageUsed / (1024 * 1024)).toFixed(1),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: ((user.storageUsed / user.storageLimit) * 100).toFixed(0),
        error: errorMsg,
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    if (!user.googleId && !await bcrypt.compare(currentPassword, user.password)) {
      const errorMsg = 'Incorrect password';
      if (isAjax) {
        return res.status(400).json({ success: false, message: errorMsg });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: (user.storageUsed / (1024 * 1024)).toFixed(1),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: ((user.storageUsed / user.storageLimit) * 100).toFixed(0),
        error: errorMsg,
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    const existingUser = await User.findOne({
      $or: [{ username }, { email }],
      _id: { $ne: req.session.userId }
    });
    if (existingUser) {
      const errorMsg = 'Username or email taken';
      if (isAjax) {
        return res.status(400).json({ success: false, message: errorMsg });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: (user.storageUsed / (1024 * 1024)).toFixed(1),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: ((user.storageUsed / user.storageLimit) * 100).toFixed(0),
        error: errorMsg,
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    user.username = username;
    user.email = email;
    user.profession = profession;
    await user.save();

    if (isAjax) {
      return res.json({ success: true, message: 'Profile updated successfully' });
    }
    res.redirect('/account');
  } catch (err) {
    console.error('Update profile error:', err);
    const errorMsg = 'Server error';
    if (req.get('X-Requested-With') === 'XMLHttpRequest') {
      return res.status(500).json({ success: false, message: errorMsg });
    }
    res.status(500).render('account', {
      user: req.user,
      storageUsedMB: (req.user.storageUsed / (1024 * 1024)).toFixed(1),
      storageLimitMB: req.user.storageLimit / (1024 * 1024),
      storagePercentage: ((req.user.storageUsed / user.storageLimit) * 100).toFixed(0),
      error: errorMsg,
      success: null,
      note: req.note ? req.note.content : ''
    });
  }
});

app.post('/account/update-password', isAuthenticated, formUpload, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
    if (user.googleId) {
      const errorMsg = 'Google users cannot change passwords';
      if (req.get('X-Requested-With') === 'XMLHttpRequest') {
        return res.status(400).json({ success: false, message: errorMsg });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: (user.storageUsed / (1024 * 1024)).toFixed(1),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: ((user.storageUsed / user.storageLimit) * 100).toFixed(0),
        error: errorMsg,
        success: null,
        note: req.note ? req.note.content : ''
      });
    }
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const isAjax = req.get('X-Requested-With') === 'XMLHttpRequest';

    if (!currentPassword || !newPassword || !confirmPassword) {
      const errorMsg = 'All fields required';
      if (isAjax) {
        return res.status(400).json({ success: false, message: errorMsg });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: (user.storageUsed / (1024 * 1024)).toFixed(1),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: ((user.storageUsed / user.storageLimit) * 100).toFixed(0),
        error: errorMsg,
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    if (!await bcrypt.compare(currentPassword, user.password)) {
      const errorMsg = 'Incorrect password';
      if (isAjax) {
        return res.status(400).json({ success: false, message: errorMsg });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: (user.storageUsed / (1024 * 1024)).toFixed(1),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: ((user.storageUsed / user.storageLimit) * 100).toFixed(0),
        error: errorMsg,
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    if (newPassword !== confirmPassword) {
      const errorMsg = 'Passwords do not match';
      if (isAjax) {
        return res.status(400).json({ success: false, message: errorMsg });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: (user.storageUsed / (1024 * 1024)).toFixed(1),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: ((user.storageUsed / user.storageLimit) * 100).toFixed(0),
        error: errorMsg,
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    if (isAjax) {
      return res.json({ success: true, message: 'Password updated successfully' });
    }
    res.redirect('/account');
  } catch (err) {
    console.error('Update password error:', err);
    const errorMsg = 'Server error';
    if (req.get('X-Requested-With') === 'XMLHttpRequest') {
      return res.status(500).json({ success: false, message: errorMsg });
    }
    res.status(500).render('account', {
      user: req.user,
      storageUsedMB: (req.user.storageUsed / (1024 * 1024)).toFixed(1),
      storageLimitMB: req.user.storageLimit / (1024 * 1024),
      storagePercentage: ((req.user.storageUsed / user.storageLimit) * 100).toFixed(0),
      error: errorMsg,
      success: null,
      note: req.note ? req.note.content : ''
    });
  }
});

app.post('/account/delete', isAuthenticated, formUpload, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
    const { password, confirmDelete } = req.body;
    const isAjax = req.get('X-Requested-With') === 'XMLHttpRequest';

    if (!confirmDelete || (!user.googleId && !password)) {
      const errorMsg = 'Password and confirmation required';
      if (isAjax) {
        return res.status(400).json({ success: false, message: errorMsg });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: (user.storageUsed / (1024 * 1024)).toFixed(1),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: ((user.storageUsed / user.storageLimit) * 100).toFixed(0),
        error: errorMsg,
        success: null,
        note: req.note ? req.note.content : ''
      });
    }

    if (!user.googleId && !await bcrypt.compare(password, user.password)) {
      const errorMsg = 'Incorrect password';
      if (isAjax) {
        return res.status(400).json({ success: false, message: errorMsg });
      }
      return res.status(400).render('account', {
        user,
        storageUsedMB: (user.storageUsed / (1024 * 1024)).toFixed(1),
        storageLimitMB: user.storageLimit / (1024 * 1024),
        storagePercentage: ((user.storageUsed / user.storageLimit) * 100).toFixed(0),
        error: errorMsg,
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
    await Note.deleteOne({ user: user._id });
    await Feedback.deleteMany({ user: user._id });
    await Message.deleteMany({ user: user._id });
    await User.deleteOne({ _id: user._id });

    return req.session.destroy(err => {
      if (err) {
        console.error('Session destroy error:', err);
        const errorMsg = 'Failed to delete account';
        if (isAjax) {
          return res.status(500).json({ success: false, message: errorMsg });
        }
        return res.status(500).render('error', { message: errorMsg, user: null, note: '' });
      }

      res.clearCookie('connect.sid');
      if (isAjax) {
        return res.json({ success: true, message: 'Account deleted successfully', redirect: '/' });
      }
      res.redirect('/');
    });
  } catch (err) {
    console.error('Delete account error:', err);
    const errorMsg = 'Server error';
    if (req.get('X-Requested-With') === 'XMLHttpRequest') {
      return res.status(500).json({ success: false, message: errorMsg });
    }
    res.status(500).render('account', {
      user: req.user,
      storageUsedMB: (req.user.storageUsed / (1024 * 1024)).toFixed(1),
      storageLimitMB: req.user.storageLimit / (1024 * 1024),
      storagePercentage: ((req.user.storageUsed / user.storageLimit) * 100).toFixed(0),
      error: errorMsg,
      success: null,
      note: req.note ? req.note.content : ''
    });
  }
});

app.post('/notes/save', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot save notes' });
    }
    const { content } = req.body;
    let note = await Note.findOne({ user: req.session.userId });
    const sanitizedContent = sanitizeHtml(content || '', {
      allowedTags: ['b', 'i', 'u', 'br'],
      allowedAttributes: {}
    });
    if (!note) {
      note = new Note({
        user: req.session.userId,
        content: sanitizedContent
      });
    } else {
      note.content = sanitizedContent;
      note.updatedAt = new Date();
    }
    await note.save();
    res.json({ success: true });
  } catch (err) {
    console.error('Save note error:', err);
    res.status(500).json({ success: false, message: 'Failed to save note' });
  }
});

app.get('/explore/search', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot access this route' });
    }
    const { query } = req.query;
    if (!query) {
      return res.json({ books: [] });
    }
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
    res.json({ books: [...publicBooks, ...accessibleBooks] });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/library/search', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot access this route' });
    }
    const { query } = req.query;
    if (!query) {
      return res.json({ books: [] });
    }
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
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/feedback', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot submit feedback' });
    }
    const { content } = req.body;
    if (!content || content.trim() === '') {
      return res.status(400).json({ success: false, message: 'Feedback content is required' });
    }
    const sanitizedContent = sanitizeHtml(content, {
      allowedTags: [],
      allowedAttributes: {}
    });
    const feedback = new Feedback({
      user: req.session.userId,
      content: sanitizedContent
    });
    await feedback.save();
    res.json({ success: true, message: 'Feedback submitted successfully' });
  } catch (err) {
    console.error('Feedback submission error:', err);
    res.status(500).json({ success: false, message: 'Failed to submit feedback' });
  }
});

app.get('/news', isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    if (user.isAdmin) {
      return res.redirect('/admin');
    }
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const newBooks = await Book.find({
      uploadDate: { $gte: today },
      visibility: { $in: ['public', 'restricted'] },
      uploadedBy: { $ne: null }
    }).populate('uploadedBy', 'username').lean();

    const pendingRequests = await Request.find({
      requestedBy: user._id,
      status: 'pending'
    }).select('book').lean();
    const pendingBookIds = pendingRequests.map(req => req.book.toString());

    const news = await News.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('postedBy', 'username')
      .lean();

    const booksWithStatus = newBooks.map(book => {
      const hasAccess = (
        Array.isArray(book.accessList) && book.accessList.some(id => id.toString() === user._id.toString())
      ) || (
        book.uploadedBy && book.uploadedBy._id && book.uploadedBy._id.toString() === user._id.toString()
      );
      return {
        ...book,
        hasPendingRequest: pendingBookIds.includes(book._id.toString()),
        hasAccess
      };
    });

    res.render('news', {
      newBooks: booksWithStatus,
      news,
      user,
      note: req.note ? req.note.content : ''
    });
  } catch (err) {
    console.error('News route error:', err.stack);
    res.status(500).render('error', { message: 'Failed to load news page', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.get('/news-image/:newsId', async (req, res) => {
  try {
    const news = await News.findById(req.params.newsId);
    if (!news || !news.image) {
      return res.status(404).send('Image not found');
    }
    res.set({
      'Content-Type': news.imageType || 'image/jpeg',
      'Content-Disposition': `inline; filename="news-${news._id}.jpg"`
    });
    res.send(news.image);
  } catch (err) {
    console.error('News image fetch error:', err);
    res.status(500).send('Failed to load image');
  }
});

app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const professions = ['BookHive'];
    const conversations = {};

    for (const profession of professions) {
      const messages = await Message.find({ profession })
        .sort({ timestamp: -1 })
        .limit(50)
        .populate('user', 'username')
        .lean();
      conversations[profession] = messages.reverse();
    }

    res.render('admin', {
      user: req.user,
      conversations,
      success: req.query.success || null,
      error: req.query.error || null,
      note: req.note ? req.note.content : ''
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.status(500).render('error', { message: 'Failed to load admin dashboard', user: req.user, note: req.note ? req.note.content : '' });
  }
});

app.post('/admin/news/post', isAuthenticated, isAdmin, newsImageUpload.single('image'), async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content) {
      return res.redirect('/admin?error=Title and content are required');
    }
    const sanitizedTitle = sanitizeHtml(title, {
      allowedTags: ['b', 'i', 'u', 'strong', 'em'],
      allowedAttributes: {}
    });
    const sanitizedContent = sanitizeHtml(content, {
      allowedTags: ['p', 'br', 'b', 'i', 'u', 'strong', 'em', 'h1', 'h2', 'h3', 'h4', 'ul', 'ol', 'li', 'a', 'span'],
      allowedAttributes: {
        'a': ['href', 'title'],
        'span': ['style']
      },
      allowedStyles: {
        'span': {
          'color': [/^#(0-9a-fA-F]{6})$/],
          'font-size': [/^\d+(px|em|rem)$/],
          'font-weight': [/^bold$/],
          'font-style': [/^italic$/],
          'text-decoration': [/^underline$/]
        }
      }
    });

    const newsData = {
      title: sanitizedTitle,
      content: sanitizedContent,
      postedBy: req.session.userId
    };

    if (req.file) {
      newsData.image = req.file.buffer;
      newsData.imageType = req.file.mimetype;
    }

    const news = new News(newsData);
    await news.save();
    res.redirect('/admin?success=News posted successfully');
  } catch (err) {
    console.error('News post error:', err);
    res.redirect('/admin?error=Failed to post news');
  }
});

app.post('/request-access', isAuthenticated, async (req, res) => {
  try {
    const { bookId } = req.body;
    const user = req.user;

    console.log(`Processing access request: bookId=${bookId}, userId=${user._id}`);

    if (!bookId) {
      return res.status(400).json({ success: false, message: 'Book ID is required' });
    }

    if (user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admins cannot request access' });
    }

    const book = await Book.findById(bookId).populate('uploadedBy', 'username profession');
    if (!book) {
      console.error(`Book not found: bookId=${bookId}`);
      return res.status(404).json({ success: false, message: 'Book not found' });
    }

    if (book.visibility !== 'restricted' || book.uploadedBy.toString() === user._id || book.accessList.includes(user._id)) {
      console.log(`Access not required: visibility=${book.visibility}, isOwner=${book.uploadedBy.toString() === user._id}, hasAccess=${book.accessList.includes(user._id)}`);
      return res.status(400).json({ success: false, message: 'Access already granted or not required' });
    }

    const existingRequest = await Request.findOne({
      book: bookId,
      requestedBy: user._id,
      status: 'pending'
    });
    if (existingRequest) {
      console.log(`Existing pending request found: requestId=${existingRequest._id}`);
      return res.status(400).json({ success: false, message: 'Access request already pending' });
    }

    const accessRequest = new Request({
      book: bookId,
      requestedBy: user._id,
      bookOwner: book.uploadedBy._id,
      status: 'pending'
    });
    await accessRequest.save();
    console.log(`Access request created: requestId=${accessRequest._id}`);

    const notificationMessage = new Message({
      user: user._id,
      profession: book.uploadedBy.profession,
      content: `${user.username} has requested access to your book "${book.title}".`
    });
    await notificationMessage.save();

    const populatedMessage = await Message.findById(notificationMessage._id).populate('user', 'username');
    io.to(book.uploadedBy.profession).emit('chatMessage', populatedMessage);
    io.to(book.uploadedBy._id.toString()).emit('notification', {
      message: `${user.username} has requested access to your book "${book.title}".`,
      requestId: accessRequest._id
    });

    res.setHeader('Content-Type', 'application/json');
    return res.json({ success: true, message: 'Access request sent successfully' });
  } catch (err) {
    console.error('Request access error:', err);
    res.setHeader('Content-Type', 'application/json');
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});