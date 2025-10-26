// server.js (đã chỉnh sửa cho live)
const admin = require('firebase-admin');
require('dotenv').config();
const express = require('express');
const fs = require('fs');
const { createReadStream } = require('fs');
const path = require('path');
const multer = require('multer');
const cors = require('cors');
const crypto = require('crypto');

// Khởi tạo Firebase Admin
let firebaseConfig;
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  firebaseConfig = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else {
  throw new Error('Missing FIREBASE_SERVICE_ACCOUNT environment variable');
}

admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});
const app = express();
const port = process.env.PORT || 3001;

// Middleware để lấy baseUrl dynamic
app.use((req, res, next) => {
  const protocol = req.headers['x-forwarded-proto'] || 'http';
  const host = req.headers.host;
  req.baseUrl = `${protocol}://${host}`;
  next();
});

// Đọc key và IV từ file .env
const encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const iv = Buffer.from(process.env.IV, 'hex');

// Kiểm tra độ dài key và IV
if (encryptionKey.length !== 32) {
  throw new Error('ENCRYPTION_KEY phải là chuỗi hex 64 ký tự (32 byte)');
}
if (iv.length !== 16) {
  throw new Error('IV phải là chuỗi hex 32 ký tự (16 byte)');
}

// Middleware xác thực Firebase JWT
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email
    };
    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).json({ error: 'Access denied. Invalid token.' });
  }
};

// Hàm tạo tên file tránh trùng
function generateUniqueFilename(originalName, uploadDir) {
  const baseName = path.parse(originalName).name;
  const ext = path.parse(originalName).ext;
  let files = [];
  try {
    files = fs.readdirSync(uploadDir).map(f => Buffer.from(f, 'latin1').toString('utf8'));
  } catch (err) {
    console.error('Error reading directory:', err);
    files = [];
  }

  let newName = originalName;
  let counter = 1;

  while (files.includes(newName)) {
    newName = `${baseName}(${counter})${ext}`;
    counter++;
  }

  return newName;
}

// Cấu hình storage cho multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'Uploads');
    if (!fs.existsSync(uploadDir)) {
      try {
        fs.mkdirSync(uploadDir, { recursive: true });
        console.log('Created uploads directory:', uploadDir);
      } catch (err) {
        console.error('Error creating uploads directory:', err);
        return cb(err);
      }
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
    const uploadDir = path.join(__dirname, 'Uploads');
    const uniqueName = generateUniqueFilename(originalName, uploadDir);
    cb(null, uniqueName);
  }
});

// Bộ lọc loại file
const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg',
    'image/png',
    'application/pdf',
    'text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  ];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Chỉ hỗ trợ file JPG, PNG, PDF, TXT, DOC, DOCX, XLS, XLSX'), false);
  }
};

const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter });

// Cấu hình CORS cho domain live
app.use(cors({ origin: 'https://da-ltmmt.web.app' })); // Thay bằng URL Firebase của bạn
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Route để xem nội dung file
app.get('/view/:filename', authenticate, async (req, res) => {
  const filename = decodeURIComponent(req.params.filename);
  const filePath = path.join(__dirname, 'Uploads', filename);
  console.log(`View attempt by ${req.user.email} for file: ${filename}`);

  // Kiểm tra quyền sở hữu
  const fileRef = admin.database().ref(`files/${req.user.uid}`);
  try {
    const snapshot = await fileRef.orderByChild('name').equalTo(filename).once('value');
    if (!snapshot.exists()) {
      console.log(`Unauthorized access attempt by ${req.user.email} to file ${filename}`);
      return res.status(403).json({ error: 'You do not have permission to access this file' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    const contentType = getContentType(filename);
    res.setHeader('Content-Type', contentType);
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
    const readStream = createReadStream(filePath);
    let decryptedStream = readStream.pipe(decipher);

    if (contentType.includes('text/plain')) {
      let chunks = [];
      decryptedStream.on('data', (chunk) => chunks.push(chunk));
      decryptedStream.on('end', () => {
        const decrypted = Buffer.concat(chunks).toString('utf8');
        res.send(decrypted);
      });
      decryptedStream.on('error', (err) => {
        console.error('Error streaming decrypted file:', err);
        res.status(500).json({ error: 'Failed to decrypt file: ' + err.message });
      });
    } else {
      decryptedStream.pipe(res).on('error', (err) => {
        console.error('Error streaming decrypted file:', err);
        res.status(500).json({ error: 'Failed to decrypt file: ' + err.message });
      });
    }
  } catch (err) {
    console.error('Error checking file ownership:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Route proxy để lấy URL tạm thời cho xem file
app.post('/proxy-view', authenticate, async (req, res) => {
  const { viewUrl } = req.body;
  if (!viewUrl) {
    return res.status(400).json({ error: 'No viewUrl provided' });
  }

  const filename = decodeURIComponent(viewUrl.split('/view/')[1]);
  const filePath = path.join(__dirname, 'Uploads', filename);

  // Kiểm tra quyền sở hữu
  const fileRef = admin.database().ref(`files/${req.user.uid}`);
  try {
    const snapshot = await fileRef.orderByChild('name').equalTo(filename).once('value');
    if (!snapshot.exists()) {
      return res.status(403).json({ error: 'You do not have permission to access this file' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Tạo token tạm thời để truy cập file
    const tempToken = crypto.randomBytes(16).toString('hex');
    const tempRef = admin.database().ref(`temp-tokens/${tempToken}`);
    await tempRef.set({
      filename,
      ownerUid: req.user.uid,
      expiryTime: Date.now() + 10 * 60 * 1000, // Thời hạn 10 phút
    });

    const tempUrl = `${req.baseUrl}/temp-view/${tempToken}`;
    res.json({ tempUrl });
  } catch (err) {
    console.error('Error generating temporary URL:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Route để truy cập file qua token tạm thời cho xem
app.get('/temp-view/:tempToken', async (req, res) => {
  const tempToken = req.params.tempToken;
  const tempRef = admin.database().ref(`temp-tokens/${tempToken}`);

  try {
    const snapshot = await tempRef.once('value');
    if (!snapshot.exists()) {
      return res.status(404).json({ error: 'Temporary token not found or expired' });
    }

    const tempData = snapshot.val();
    if (tempData.expiryTime < Date.now()) {
      await tempRef.remove();
      return res.status(410).json({ error: 'Temporary token has expired' });
    }

    const filePath = path.join(__dirname, 'Uploads', tempData.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.setHeader('Content-Type', getContentType(tempData.filename));
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
    createReadStream(filePath).pipe(decipher).pipe(res).on('error', (err) => {
      console.error('Error streaming decrypted file:', err);
      res.status(500).json({ error: 'Failed to decrypt file: ' + err.message });
    });
  } catch (err) {
    console.error('Error accessing file with temporary token:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Route proxy để lấy URL tạm thời cho tải xuống
app.post('/proxy-download', authenticate, async (req, res) => {
  const { downloadUrl } = req.body;
  if (!downloadUrl) {
    return res.status(400).json({ error: 'No downloadUrl provided' });
  }

  const filename = decodeURIComponent(downloadUrl.split('/uploads/')[1]);
  const filePath = path.join(__dirname, 'Uploads', filename);

  // Kiểm tra quyền sở hữu
  const fileRef = admin.database().ref(`files/${req.user.uid}`);
  try {
    const snapshot = await fileRef.orderByChild('name').equalTo(filename).once('value');
    if (!snapshot.exists()) {
      return res.status(403).json({ error: 'You do not have permission to access this file' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Tạo token tạm thời để tải xuống
    const tempToken = crypto.randomBytes(16).toString('hex');
    const tempRef = admin.database().ref(`temp-tokens/${tempToken}`);
    await tempRef.set({
      filename,
      ownerUid: req.user.uid,
      expiryTime: Date.now() + 10 * 60 * 1000, // Thời hạn 10 phút
    });

    const tempUrl = `${req.baseUrl}/temp-download/${tempToken}`;
    res.json({ tempUrl });
  } catch (err) {
    console.error('Error generating temporary download URL:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Route để tải file qua token tạm thời
app.get('/temp-download/:tempToken', async (req, res) => {
  const tempToken = req.params.tempToken;
  const tempRef = admin.database().ref(`temp-tokens/${tempToken}`);

  try {
    const snapshot = await tempRef.once('value');
    if (!snapshot.exists()) {
      return res.status(404).json({ error: 'Temporary token not found or expired' });
    }

    const tempData = snapshot.val();
    if (tempData.expiryTime < Date.now()) {
      await tempRef.remove();
      return res.status(410).json({ error: 'Temporary token has expired' });
    }

    const filePath = path.join(__dirname, 'Uploads', tempData.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(tempData.filename)}`);
    res.setHeader('Content-Type', getContentType(tempData.filename));
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
    createReadStream(filePath).pipe(decipher).pipe(res).on('error', (err) => {
      console.error('Error streaming decrypted file:', err);
      res.status(500).json({ error: 'Failed to decrypt file: ' + err.message });
    });
  } catch (err) {
    console.error('Error accessing file with temporary token:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Route để tải file
app.get('/uploads/:filename', authenticate, async (req, res) => {
  const filename = decodeURIComponent(req.params.filename);
  const filePath = path.join(__dirname, 'Uploads', filename);
  console.log(`Download attempt by ${req.user.email} for file: ${filename}`);

  // Kiểm tra quyền sở hữu
  const fileRef = admin.database().ref(`files/${req.user.uid}`);
  try {
    const snapshot = await fileRef.orderByChild('name').equalTo(filename).once('value');
    if (!snapshot.exists()) {
      console.log(`Unauthorized download attempt by ${req.user.email} to file ${filename}`);
      return res.status(403).json({ error: 'You do not have permission to access this file' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
    res.setHeader('Content-Type', getContentType(filename));
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
    createReadStream(filePath).pipe(decipher).pipe(res).on('error', (err) => {
      console.error('Error streaming decrypted file:', err);
      res.status(500).json({ error: 'Failed to decrypt file: ' + err.message });
    });
  } catch (err) {
    console.error('Error checking file ownership:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Route để xóa file
app.delete('/delete/:filename', authenticate, async (req, res) => {
  const filename = decodeURIComponent(req.params.filename);
  const filePath = path.join(__dirname, 'Uploads', filename);
  console.log(`Delete attempt by ${req.user.email} for file: ${filename}`);

  // Kiểm tra quyền sở hữu
  const fileRef = admin.database().ref(`files/${req.user.uid}`);
  try {
    const snapshot = await fileRef.orderByChild('name').equalTo(filename).once('value');
    if (!snapshot.exists()) {
      console.log(`Unauthorized delete attempt by ${req.user.email} to file ${filename}`);
      return res.status(403).json({ error: 'You do not have permission to delete this file' });
    }

    if (fs.existsSync(filePath)) {
      fs.unlink(filePath, (err) => {
        if (err) {
          console.error('Error deleting file:', err);
          return res.status(500).json({ error: 'Failed to delete file' });
        }
        // Xóa metadata từ Firebase
        snapshot.forEach((childSnapshot) => {
          childSnapshot.ref.remove();
        });
        res.json({ message: 'File deleted successfully' });
      });
    } else {
      res.status(404).json({ error: 'File not found' });
    }
  } catch (err) {
    console.error('Error checking file ownership:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Route để upload file
app.post('/upload', authenticate, upload.single('file'), async (req, res) => {
  console.log('Upload attempt by user:', req.user.email);

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const filename = req.file.filename;
  const filePath = path.join(__dirname, 'Uploads', filename);

  // Kiểm tra xem file đã tồn tại trong metadata của user chưa
  const fileRef = admin.database().ref(`files/${req.user.uid}`);
  try {
    const snapshot = await fileRef.orderByChild('name').equalTo(filename).once('value');
    if (snapshot.exists()) {
      return res.status(409).json({ error: 'File with this name already exists' });
    }

    // Mã hóa file
    let input;
    if (req.file.mimetype === 'text/plain') {
      input = fs.readFileSync(filePath, 'utf8');
    } else {
      input = fs.readFileSync(filePath);
    }

    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
    let encrypted;
    if (typeof input === 'string') {
      encrypted = Buffer.concat([cipher.update(Buffer.from(input, 'utf8')), cipher.final()]);
    } else {
      encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
    }

    fs.writeFileSync(filePath, encrypted);
    const fileUrl = `${req.baseUrl}/uploads/${filename}`;

    // Lưu metadata vào Firebase
    const newFileRef = admin.database().ref(`files/${req.user.uid}/${Date.now()}`);
    await newFileRef.set({
      name: filename,
      viewUrl: fileUrl.replace('/uploads/', '/view/'),
      downloadUrl: fileUrl,
      type: req.file.mimetype,
      size: req.file.size,
      uploadedAt: new Date().toISOString()
    });

    res.json({
      url: fileUrl,
      filename: filename,
      message: 'File uploaded successfully'
    });
  } catch (err) {
    console.error('Error processing file:', err);
    res.status(500).json({ error: 'Failed to process file: ' + err.message });
  }
});

// Route để liệt kê file
app.get('/files', authenticate, async (req, res) => {
  console.log(`List files request from ${req.user.email}`);
  const fileRef = admin.database().ref(`files/${req.user.uid}`);
  try {
    const snapshot = await fileRef.once('value');
    const filesData = snapshot.val() || {};
    const fileList = Object.values(filesData).map(file => ({
      name: file.name,
      url: file.downloadUrl
    }));
    res.json(fileList);
  } catch (err) {
    console.error('Error reading files from Firebase:', err);
    res.status(500).json({ error: 'Cannot read files' });
  }
});

app.get('/', (req, res) => {
  res.send('File Storage Server is running');
});

// Hàm xác định Content-Type
function getContentType(filename) {
  const ext = path.extname(filename).toLowerCase();
  switch (ext) {
    case '.txt':
      return 'text/plain; charset=utf-8';
    case '.pdf':
      return 'application/pdf';
    case '.doc':
      return 'application/msword';
    case '.docx':
      return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    case '.xls':
      return 'application/vnd.ms-excel';
    case '.xlsx':
      return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    case '.jpg':
    case '.jpeg':
      return 'image/jpeg';
    case '.png':
      return 'image/png';
    default:
      return 'application/octet-stream';
  }
}

// Middleware xử lý lỗi multer
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File vượt quá giới hạn 10MB' });
    }
  }
  console.error('Global error:', err.message);
  res.status(500).json({ error: 'Đã xảy ra lỗi server: ' + err.message });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});