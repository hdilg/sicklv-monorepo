// server.js — إصدار آمن جداً

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

// Middleware الحماية: Helmet + CSP
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: [],
    frameAncestors: ["'none'"]
  }
}));

// إعداد CORS للسماح فقط لمصدر محدد (أمان عالي)
app.use(cors({
  origin: ['http://localhost:3000'], // عدّله إذا لديك نطاق حقيقي
  optionsSuccessStatus: 200
}));

// الحد من عدد الطلبات = حماية من DDoS / Brute Force
app.use('/api/', rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { success: false, message: 'تجاوزت الحد المسموح، حاول بعد قليل.' }
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname)));

// معلومات الإجازات المخزنة
const leaves = [
  {
    serviceCode: "GSL25021372778",
    idNumber: "1088576044",
    name: "عبدالاله سليمان عبدالله الهديلج",
    reportDate: "2025-02-09",
    startDate: "2025-02-09",
    endDate: "2025-02-24",
    doctorName: "هدى مصطفى خضر دحبور",
    jobTitle: "استشاري",
    days: 16,
  },
  // ... بيانات إضافية
];

// API endpoint محمي بالتحقق من الإدخالات
app.post('/api/leave', (req, res) => {
  const { serviceCode, idNumber } = req.body;

  if (
    typeof serviceCode !== 'string' ||
    typeof idNumber !== 'string' ||
    !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
    !/^[0-9]{10}$/.test(idNumber)
  ) {
    return res.status(400).json({ success: false, message: 'البيانات غير صحيحة.' });
  }

  const match = leaves.find(l =>
    l.serviceCode === serviceCode && l.idNumber === idNumber
  );

  return match
    ? res.json({ success: true, record: match })
    : res.status(404).json({ success: false, message: 'لا يوجد سجل مطابق.' });
});

// معالجة الصفحات غير الموجودة
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'الصفحة غير موجودة.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🔐 الخادم الخلفي الآمن يعمل على المنفذ: ${PORT}`));
