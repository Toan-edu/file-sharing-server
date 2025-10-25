const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3001; // Sử dụng cổng từ Render hoặc mặc định 3001

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('uploads'));

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const fileUrl = `${req.protocol}://${req.get('host')}/${req.file.filename}`;
  res.json({ url: fileUrl });
});

app.get('/files', (req, res) => {
  const uploadDir = path.join(__dirname, 'uploads');
  fs.readdir(uploadDir, (err, files) => {
    if (err) return res.status(500).json({ error: 'Cannot read files' });
    const fileList = files.map(file => ({
      name: file,
      url: `${req.protocol}://${req.get('host')}/${file}`
    }));
    res.json(fileList);
  });
});

app.get('/', (req, res) => {
  res.send('File Storage Server is running');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});