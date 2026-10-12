require('dotenv').config();
const express = require('express'), mongoose = require('mongoose'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), multer = require('multer'), fs = require('fs'), path = require('path');
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
fs.mkdirSync('uploads', { recursive: true });
const SECRET = process.env.JWT_SECRET || 'dev-secret';
const upload = multer({ dest: 'uploads/', limits: { fileSize: 5e6 } });
const { Schema, model } = mongoose, Id = Schema.Types.ObjectId;

// ---------- Models ----------
const User = model('User', new Schema({
  name: String, email: { type: String, unique: true, lowercase: true, required: true },
  password: String, active: { type: Boolean, default: true },
  role: { type: String, enum: ['student', 'officer', 'recruiter', 'admin'], default: 'student' }
}, { timestamps: true }));
const Student = model('Student', new Schema({
  user: { type: Id, ref: 'User', unique: true }, regNo: String, phone: String, dob: String,
  department: String, course: String, batch: String, cgpa: { type: Number, default: 0 },
  tenth: { type: Number, default: 0 }, twelfth: { type: Number, default: 0 }, backlogs: { type: Number, default: 0 },
  skills: [String], github: String, linkedin: String, resume: { file: String, name: String }
}));
const Company = model('Company', new Schema({
  name: { type: String, required: true }, industry: String, location: String,
  website: String, description: String, contactPerson: String, contactEmail: String
}));
const Drive = model('Drive', new Schema({
  company: { type: Id, ref: 'Company', required: true }, role: String, package: Number, location: String,
  deadline: Date, driveDate: Date, minCgpa: { type: Number, default: 0 }, min10: { type: Number, default: 0 },
  min12: { type: Number, default: 0 }, maxBacklogs: { type: Number, default: 0 }, departments: [String]
}, { timestamps: true }));
const STATUS = ['Applied', 'Shortlisted', 'Test', 'Interview', 'Selected', 'Rejected', 'Withdrawn'];
const Application = model('Application', new Schema({
  drive: { type: Id, ref: 'Drive' }, student: { type: Id, ref: 'Student' },
  status: { type: String, enum: STATUS, default: 'Applied' },
  interviews: [{ round: String, date: Date, mode: String, link: String, result: String,
    questions: [{ question: String, answer: String }] }]
}, { timestamps: true }).index({ drive: 1, student: 1 }, { unique: true }));

// ---------- Helpers ----------
const w = f => (q, s, n) => f(q, s, n).catch(e => s.status(e.code === 11000 ? 409 : 400)
  .json({ error: e.code === 11000 ? 'Already exists' : e.message }));
const tok = u => ({ token: jwt.sign({ id: u._id }, SECRET, { expiresIn: '7d' }), user: { name: u.name, email: u.email, role: u.role } });
const auth = (...roles) => async (req, res, next) => {
  try {
    const p = jwt.verify((req.headers.authorization || '').slice(7) || req.query.token, SECRET);
    const u = await User.findById(p.id);
    if (!u || !u.active) throw 0;
    if (roles.length && !roles.includes(u.role)) return res.status(403).json({ error: 'Not allowed for your role' });
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Please log in again' }); }
};
const list = v => (Array.isArray(v) ? v : String(v || '').split(',')).map(x => x.trim()).filter(Boolean);
const eligible = (s, d) => s.cgpa >= d.minCgpa && s.tenth >= d.min10 && s.twelfth >= d.min12 &&
  s.backlogs <= d.maxBacklogs && (!d.departments.length || d.departments.includes(s.department));
const myStudent = req => Student.findOne({ user: req.user._id });
const STAFF = ['officer', 'admin'], HIRE = ['officer', 'recruiter', 'admin'];

// ---------- Auth ----------
app.post('/api/register', w(async (q, s) => {
  const { name, email, password, regNo, department } = q.body;
  if (!password || password.length < 6) throw Error('Password needs at least 6 characters');
  const u = await User.create({ name, email, password: await bcrypt.hash(password, 10), role: 'student' });
  await Student.create({ user: u._id, regNo, department });
  s.json(tok(u));
}));
app.post('/api/login', w(async (q, s) => {
  const u = await User.findOne({ email: String(q.body.email).toLowerCase() });
  if (!u || !(await bcrypt.compare(q.body.password || '', u.password))) throw Error('Wrong email or password');
  if (!u.active) throw Error('This account is deactivated');
  s.json(tok(u));
}));

// ---------- Student profile & resume ----------
app.get('/api/profile', auth('student'), w(async (q, s) => s.json(await myStudent(q))));
app.put('/api/profile', auth('student'), w(async (q, s) => {
  const b = q.body, st = await myStudent(q);
  ['regNo', 'phone', 'dob', 'department', 'course', 'batch', 'github', 'linkedin'].forEach(k => b[k] !== undefined && (st[k] = b[k]));
  ['cgpa', 'tenth', 'twelfth', 'backlogs'].forEach(k => b[k] !== undefined && b[k] !== '' && (st[k] = Number(b[k])));
  if (b.skills !== undefined) st.skills = list(b.skills);
  s.json(await st.save());
}));
app.post('/api/profile/resume', auth('student'), upload.single('resume'), w(async (q, s) => {
  if (!q.file || q.file.mimetype !== 'application/pdf') throw Error('Upload a PDF file (max 5 MB)');
  const st = await myStudent(q);
  st.resume = { file: q.file.filename, name: q.file.originalname };
  s.json(await st.save());
}));
app.get('/api/students/:id/resume', auth(...HIRE), w(async (q, s) => {
  const st = await Student.findById(q.params.id);
  if (!st?.resume?.file) throw Error('No resume uploaded');
  s.download(path.join(__dirname, 'uploads', st.resume.file), st.resume.name);
}));
app.get('/api/students', auth(...STAFF), w(async (q, s) =>
  s.json(await Student.find().populate('user', 'name email').sort('-cgpa'))));

// ---------- Companies & drives ----------
app.get('/api/companies', auth(...HIRE), w(async (q, s) => s.json(await Company.find().sort('name'))));
app.post('/api/companies', auth(...HIRE), w(async (q, s) => s.json(await Company.create(q.body))));
app.get('/api/drives', auth(), w(async (q, s) => {
  const drives = await Drive.find().populate('company', 'name').sort('-createdAt').lean();
  if (q.user.role !== 'student') return s.json(drives);
  const st = await myStudent(q), mine = await Application.find({ student: st._id });
  s.json(drives.map(d => ({ ...d, eligible: eligible(st, d), applied: mine.some(a => String(a.drive) === String(d._id)) })));
}));
app.post('/api/drives', auth(...HIRE), w(async (q, s) =>
  s.json(await Drive.create({ ...q.body, departments: list(q.body.departments) }))));
app.post('/api/drives/:id/apply', auth('student'), w(async (q, s) => {
  const d = await Drive.findById(q.params.id), st = await myStudent(q);
  if (!d) throw Error('Drive not found');
  if (d.deadline && d.deadline < new Date()) throw Error('Application deadline has passed');
  if (!eligible(st, d)) throw Error('You do not meet the eligibility criteria');
  s.json(await Application.create({ drive: d._id, student: st._id }));
}));

// ---------- Applications ----------
app.get('/api/applications/mine', auth('student'), w(async (q, s) => {
  const st = await myStudent(q);
  s.json(await Application.find({ student: st._id }).sort('-createdAt')
    .populate({ path: 'drive', populate: { path: 'company', select: 'name' } }));
}));
app.get('/api/applications/:id', auth(), w(async (q, s) => {
  const a = await Application.findById(q.params.id);
  if (!a) throw Error('Application not found');
  if (q.user.role === 'student') {
    const st = await myStudent(q);
    if (!st || String(a.student) !== String(st._id)) throw Error('Not allowed to view this interview');
  }
  s.json(await a.populate([
    { path: 'drive', populate: { path: 'company', select: 'name' } },
    { path: 'student', populate: { path: 'user', select: 'name email' } }
  ]));
}));
app.get('/api/drives/:id/applicants', auth(...HIRE), w(async (q, s) =>
  s.json(await Application.find({ drive: q.params.id })
    .populate({ path: 'student', populate: { path: 'user', select: 'name email' } }))));
app.get('/api/interviews', auth(...HIRE), w(async (q, s) =>
  s.json(await Application.find({ 'interviews.0': { $exists: true } })
    .populate({ path: 'drive', populate: { path: 'company', select: 'name' } })
    .populate({ path: 'student', populate: { path: 'user', select: 'name email' } }))));
app.put('/api/applications/:id', auth(...HIRE), w(async (q, s) => {
  const a = await Application.findById(q.params.id);
  if (q.body.status) { if (!STATUS.includes(q.body.status)) throw Error('Invalid status'); a.status = q.body.status; }
  if (q.body.interview) a.interviews.push(q.body.interview);
  s.json(await a.save());
}));

// ---------- Stats & admin ----------
app.get('/api/stats', auth(...STAFF, 'recruiter'), w(async (q, s) => {
  const [students, companies, drives, applications, placed] = await Promise.all([
    Student.countDocuments(), Company.countDocuments(), Drive.countDocuments(), Application.countDocuments(),
    Application.distinct('student', { status: 'Selected' })]);
  s.json({ Students: students, Companies: companies, Drives: drives, Applications: applications,
    Placed: placed.length, 'Placement %': students ? Math.round(placed.length / students * 100) : 0 });
}));
app.get('/api/users', auth('admin'), w(async (q, s) => s.json(await User.find().select('-password').sort('role'))));
app.post('/api/users', auth('admin'), w(async (q, s) => {
  const { name, email, password, role } = q.body;
  if (!['officer', 'recruiter', 'admin'].includes(role)) throw Error('Invalid role');
  await User.create({ name, email, role, password: await bcrypt.hash(password || '', 10) });
  s.json({ ok: true });
}));
app.put('/api/users/:id/toggle', auth('admin'), w(async (q, s) => {
  const u = await User.findById(q.params.id);
  if (String(u._id) === String(q.user._id)) throw Error('You cannot deactivate yourself');
  u.active = !u.active; await u.save(); s.json({ active: u.active });
}));

// ---------- Start ----------
async function seed() {
  if (!(await User.countDocuments())) {
    const seedStaff = async (name, email, role) => {
      const passwordHash = await bcrypt.hash(process.env.SEED_STAFF_PASSWORD || 'password123', 10);
      return User.create({ name, email, role, password: passwordHash });
    };

    await seedStaff('Admin', 'admin@college.edu', 'admin');
    await seedStaff('Placement Officer', 'officer@college.edu', 'officer');
    await seedStaff('Recruiter', 'recruiter@abc.com', 'recruiter');
    console.log('Seeded internal staff accounts.');
  }

  const companyData = [
    { name: 'Acme Technologies', industry: 'Software', location: 'Bengaluru', website: 'https://example.com' },
    { name: 'Brightwave Analytics', industry: 'Data & Analytics', location: 'Hyderabad', website: 'https://example.com' }
  ];
  const companies = await Promise.all(companyData.map(async data =>
    await Company.findOne({ name: data.name }) || await Company.create(data)));
  if (!(await Drive.countDocuments())) {
    const deadline = new Date(Date.now() + 30 * 86400000);
    const driveDate = new Date(Date.now() + 45 * 86400000);
    await Drive.create([
      { company: companies[0]._id, role: 'Graduate Software Engineer', package: 8, location: 'Bengaluru', deadline, driveDate, minCgpa: 8, min10: 80, min12: 70, maxBacklogs: 0 },
      { company: companies[1]._id, role: 'Junior Data Analyst', package: 6, location: 'Hyderabad', deadline, driveDate, minCgpa: 8, min10: 80, min12: 70, maxBacklogs: 0 }
    ]);
  }
}
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/placement').then(async () => {
  console.log('MongoDB connected'); await seed();
  app.listen(process.env.PORT || 3000, () => console.log('Running on http://localhost:' + (process.env.PORT || 3000)));
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
