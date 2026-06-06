const express = require('express');
const multer = require('multer');
const XLSX = require('xlsx');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET || 'development-only-session-secret';

if (isProduction && !process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET is required in production');
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        secure: isProduction
    }
}));

// Ensure directories exist
const dirs = ['data', 'uploads'];
dirs.forEach(dir => {
    const dirPath = path.join(__dirname, dir);
    if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
});

// Helper functions
function readJSON(filename) {
    const filePath = path.join(__dirname, 'data', filename);
    if (!fs.existsSync(filePath)) return filename === 'students.json' ? [] : {};
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJSON(filename, data) {
    const filePath = path.join(__dirname, 'data', filename);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

// Initialize default admin if not exists
async function initAdmin() {
    let users = readJSON('users.json');
    if (!Array.isArray(users) || users.length === 0 || users[0].password === '$2a$10$defaultHashPlaceholder') {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        users = [{ username: 'admin', password: hashedPassword }];
        writeJSON('users.json', users);
        console.log('Default admin created: admin / admin123');
    }
}
initAdmin();

// Auth middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.isAuthenticated) {
        return next();
    }
    res.status(401).json({ error: 'غير مصرح' });
}

// Multer config for logo upload
const logoStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, 'logo' + ext);
    }
});
const logoUpload = multer({
    storage: logoStorage,
    fileFilter: (req, file, cb) => {
        const allowed = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowed.includes(ext)) cb(null, true);
        else cb(new Error('نوع ملف غير مدعوم'));
    }
});

// Multer config for Excel upload
const excelStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
    filename: (req, file, cb) => cb(null, 'students_data' + path.extname(file.originalname))
});
const excelUpload = multer({
    storage: excelStorage,
    fileFilter: (req, file, cb) => {
        const allowed = ['.xlsx', '.xls', '.csv'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowed.includes(ext)) cb(null, true);
        else cb(new Error('يرجى رفع ملف Excel أو CSV'));
    }
});

// ============== PUBLIC API ==============

// Get settings
app.get('/api/settings', (req, res) => {
    const settings = readJSON('settings.json');
    res.json(settings);
});

// Search students
app.get('/api/search', (req, res) => {
    const query = (req.query.q || '').trim();
    if (!query) return res.json([]);

    const students = readJSON('students.json');
    const results = students.filter(s =>
        s.civilId === query || s.seatNumber === query
    );
    res.json(results);
});

// ============== AUTH API ==============

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const users = readJSON('users.json');
    const user = users.find(u => u.username === username);

    if (!user) return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

    req.session.isAuthenticated = true;
    req.session.username = username;
    res.json({ success: true });
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Check auth status
app.get('/api/auth-status', (req, res) => {
    res.json({ isAuthenticated: !!(req.session && req.session.isAuthenticated), username: req.session?.username });
});

// ============== ADMIN API ==============

// Create user
app.post('/api/admin/create-user', requireAuth, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'يرجى إدخال اسم المستخدم وكلمة المرور' });
    if (password.length < 4) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 4 أحرف على الأقل' });

    let users = readJSON('users.json');
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'اسم المستخدم موجود بالفعل' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    writeJSON('users.json', users);
    res.json({ success: true, message: 'تم إنشاء الحساب بنجاح' });
});

// Change password
app.post('/api/admin/change-password', requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'يرجى إدخال كلمة المرور الحالية والجديدة' });
    if (newPassword.length < 4) return res.status(400).json({ error: 'كلمة المرور الجديدة يجب أن تكون 4 أحرف على الأقل' });

    let users = readJSON('users.json');
    const userIndex = users.findIndex(u => u.username === req.session.username);
    if (userIndex === -1) return res.status(404).json({ error: 'المستخدم غير موجود' });

    const valid = await bcrypt.compare(currentPassword, users[userIndex].password);
    if (!valid) return res.status(401).json({ error: 'كلمة المرور الحالية غير صحيحة' });

    users[userIndex].password = await bcrypt.hash(newPassword, 10);
    writeJSON('users.json', users);
    res.json({ success: true, message: 'تم تغيير كلمة المرور بنجاح' });
});

// Update settings
app.post('/api/admin/settings', requireAuth, (req, res) => {
    const { schoolName, pageText, studentInstructions } = req.body;
    let settings = readJSON('settings.json');
    if (schoolName !== undefined) settings.schoolName = schoolName;
    if (pageText !== undefined) settings.pageText = pageText;
    if (studentInstructions !== undefined) settings.studentInstructions = studentInstructions;
    writeJSON('settings.json', settings);
    res.json({ success: true, message: 'تم تحديث الإعدادات بنجاح' });
});

// Upload logo
app.post('/api/admin/upload-logo', requireAuth, logoUpload.single('logo'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'يرجى اختيار ملف' });
    let settings = readJSON('settings.json');
    settings.logoPath = '/uploads/' + req.file.filename;
    writeJSON('settings.json', settings);
    res.json({ success: true, message: 'تم رفع الشعار بنجاح', logoPath: settings.logoPath });
});

// Upload Excel
app.post('/api/admin/upload-excel', requireAuth, excelUpload.single('excel'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'يرجى اختيار ملف' });

    try {
        const workbook = XLSX.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        const rawData = XLSX.utils.sheet_to_json(worksheet, { defval: '' });

        // Log actual column names from the Excel file for debugging
        if (rawData.length > 0) {
            console.log('Excel columns found:', Object.keys(rawData[0]));
        }

        // Flexible keyword-based column mapping
        // Each field has keywords - if a column name CONTAINS any keyword, it maps to that field
        const fieldKeywords = [
            { field: 'studentName',       keywords: ['اسم', 'الطالب', 'name', 'student'] },
            { field: 'civilId',           keywords: ['مدني', 'المدني', 'civil', 'civilid'] },
            { field: 'seatNumber',        keywords: ['جلوس', 'الجلوس', 'seat'] },
            { field: 'schoolCommittee',   keywords: ['لجنة مدرسة', 'لجنه مدرسة', 'لجنة المدرسة', 'لجنه المدرسه', 'مدرسة', 'مدرسه', 'school'] },
            { field: 'mainCommittee',     keywords: ['رئيسية', 'رئيسيه', 'الرئيسية', 'الرئيسيه', 'main'] },
            { field: 'subCommittee',      keywords: ['فرعية', 'فرعيه', 'الفرعية', 'الفرعيه', 'sub'] },
            { field: 'committeeLocation', keywords: ['مكان', 'موقع', 'location', 'place'] },
        ];

        // Build a mapping from actual Excel column name to our field name
        function mapColumnName(colName) {
            const normalized = colName.trim().replace(/\s+/g, ' ');
            // Try exact match first
            for (const { field, keywords } of fieldKeywords) {
                for (const kw of keywords) {
                    if (normalized === kw) return field;
                }
            }
            // Then try contains match (prioritize longer keywords first to avoid false positives)
            // Sort: schoolCommittee keywords before mainCommittee/subCommittee to avoid "لجنة" matching wrong
            for (const { field, keywords } of fieldKeywords) {
                const sortedKw = [...keywords].sort((a, b) => b.length - a.length);
                for (const kw of sortedKw) {
                    if (normalized.includes(kw)) return field;
                }
            }
            return null;
        }

        // Pre-build the column mapping using the first row's keys
        const columnMapping = {};
        if (rawData.length > 0) {
            for (const colName of Object.keys(rawData[0])) {
                const mapped = mapColumnName(colName);
                if (mapped) {
                    columnMapping[colName] = mapped;
                    console.log(`  Column "${colName}" -> ${mapped}`);
                } else {
                    console.log(`  Column "${colName}" -> (unmapped)`);
                }
            }
        }

        const students = rawData.map(row => {
            const student = {};
            for (const [key, value] of Object.entries(row)) {
                const mappedField = columnMapping[key];
                if (mappedField) {
                    student[mappedField] = String(value).trim();
                }
            }
            return student;
        }).filter(s => s.studentName || s.civilId || s.seatNumber);

        writeJSON('students.json', students);
        res.json({ success: true, message: `تم رفع ${students.length} سجل بنجاح`, count: students.length });
    } catch (err) {
        console.error('Excel parse error:', err);
        res.status(500).json({ error: 'خطأ في قراءة ملف Excel' });
    }
});

// Get students count
app.get('/api/admin/students-count', requireAuth, (req, res) => {
    const students = readJSON('students.json');
    res.json({ count: students.length });
});

// Get all students (with optional search and pagination)
app.get('/api/admin/students', requireAuth, (req, res) => {
    const students = readJSON('students.json');
    const search = (req.query.search || '').trim();
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 25;

    let filtered = students;
    if (search) {
        filtered = students.filter(s =>
            (s.studentName || '').includes(search) ||
            (s.civilId || '').includes(search) ||
            (s.seatNumber || '').includes(search) ||
            (s.schoolCommittee || '').includes(search) ||
            (s.mainCommittee || '').includes(search) ||
            (s.subCommittee || '').includes(search) ||
            (s.committeeLocation || '').includes(search)
        );
    }

    const total = filtered.length;
    const totalPages = Math.ceil(total / limit);
    const start = (page - 1) * limit;
    const paged = filtered.slice(start, start + limit);

    res.json({ students: paged, total, totalPages, page });
});

// Delete all students
app.delete('/api/admin/students', requireAuth, (req, res) => {
    writeJSON('students.json', []);
    res.json({ success: true, message: 'تم حذف جميع البيانات' });
});

// Serve pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
