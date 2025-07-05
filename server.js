const express = require("express");
const path = require("path");
const session = require("express-session");
const { parse: parseCSV } = require("csv-parse"); // לקריאת קובץ CSV
const fs = require("fs");
const multer = require("multer");
const { parse } = require("json2csv"); // ודא שזה למעלה בקובץ
const https = require("https");
const bcrypt = require("bcrypt");
const usersPath = path.join(__dirname, "data", "users.json");
const loginAttemptsPath = path.join(__dirname, "data", "login_attempts.json");
function readJSON(filepath) {
  const moment = require("moment-timezone");
  const israelTime = moment.tz(new Date(), "Asia/Jerusalem").format("HH:mm");
  app.use(express.json()); // ← ואז משתמשים
  const fullPath = filepath.startsWith("/data/")
    ? filepath
    : "/data/" + filepath;

  if (!fs.existsSync(fullPath)) return [];
  const data = fs.readFileSync(fullPath, "utf-8");
  return JSON.parse(data);
}

function writeJSON(filepath, data) {
  const fullPath = filepath.startsWith("/data/")
    ? filepath
    : "/data/" + filepath;

  fs.writeFileSync(fullPath, JSON.stringify(data, null, 2), "utf-8");
}

let loginAttempts = {};
const permissions = {
  admin: [
    "add-driver",
    "edit-driver",
    "delete-driver",
    "upload-coordinations",
    "upload-drivers",
    "toggle-status",
    "manage-users",
    "view-statistics",
  ],
  bakara: ["add-driver", "edit-driver", "toggle-status"],
  supervisor: ["add-driver", "edit-driver"],
  visitor: ["view-driver"],
};

// ⬇️ כאן תוסיף את הפונקציה מחוץ לאובייקט
function can(roleOrPermissions, action) {
  if (!roleOrPermissions || !action) return false;

  // אם התקבל מערך הרשאות (permissions)
  if (Array.isArray(roleOrPermissions)) {
    return roleOrPermissions.includes(action);
  }

  // אם התקבל מחרוזת תפקיד (role רגיל)
  return (
    permissions[roleOrPermissions] &&
    permissions[roleOrPermissions].includes(action)
  );
}

// טען ניסיון התחברות קיים אם יש
if (fs.existsSync(loginAttemptsPath)) {
  loginAttempts = JSON.parse(fs.readFileSync(loginAttemptsPath, "utf8"));
}

function idSimilarity(a, b) {
  a = a.replace(/\D/g, "");
  b = b.replace(/\D/g, "");
  let matches = 0;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] === b[i]) matches++;
  }
  return matches / Math.max(a.length, b.length);
}

// שמירה לקובץ
function saveLoginAttempts() {
  fs.writeFileSync(
    loginAttemptsPath,
    JSON.stringify(loginAttempts, null, 2),
    "utf8",
  );
}

const app = express();

// תבניות EJS
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// קבצים סטטיים
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));

// Session
app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 10 * 60 * 1000, // 10 דקות = 600,000 מילישניות
    },
  }),
);
app.use((req, res, next) => {
  if (req.session) {
    req.session._garbage = Date();
    req.session.touch();
  }
  next();
});

function hasPermission(role, allowedRoles) {
  return allowedRoles.includes(role);
}

// Multer - להעלאת תמונות וקבצים
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "public", "uploads");
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath);
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage });

app.get("/driver/:id/gatepass", (req, res) => {
  const driverId = req.params.id;
  const driver = driverData[driverId];

  if (!driver) return res.status(404).send("נהג לא נמצא");

  // ❌ אם הנהג במניעה - דרוש סיסמה
  if (driver.status === "מנוע" && !req.session.gatepassApprovedForId) {
    return res.render("gatepass-password", { driverId, errorMessage: null });
  }

  let selectedCoord = null;

  if (Array.isArray(driver.coordinations)) {
    const passedCoords = driver.coordinations.filter((c) => c.passed === true);

    if (passedCoords.length === 0) {
      return res.render("error", {
        message: "לא ניתן להפיק Gate Pass – אין תיאום שעבר בקרה.",
        backLink: `/driver/${driverId}`,
      });
    }

    // מיון לפי זמן אמת (ISO)
    passedCoords.sort((a, b) => {
      const timeA = new Date(a.passedAt || 0);
      const timeB = new Date(b.passedAt || 0);
      return timeB - timeA;
    });

    selectedCoord = passedCoords[0];
  }

  res.render("gatepass", {
    driver,
    coordination: selectedCoord || null,
  });
});
app.get("/cron/save-and-reset", async (req, res) => {
  const secret = req.query.key;
  if (secret !== "xk98aZ73B7fsG1qW2s9n") {
    return res.status(403).send("⛔ לא מורשה");
  }

  const saveUrl = `https://${req.headers.host}/cron/save-statistics?key=${secret}`;
  const resetUrl = `https://${req.headers.host}/cron-reset?key=${secret}`;

  const https = require("https");

  const fetch = (url) =>
    new Promise((resolve) => {
      https
        .get(url, (res) => {
          let data = "";
          res.on("data", (chunk) => (data += chunk));
          res.on("end", () => resolve(data));
        })
        .on("error", (err) => resolve(`שגיאה: ${err.message}`));
    });

  const saveResult = await fetch(saveUrl);
  const resetResult = await fetch(resetUrl);

  res.send(`✅ שמירה: ${saveResult}<br>🔁 איפוס: ${resetResult}`);
});

// פונקציות עזר
function ensureLoggedIn(req, res, next) {
  if (req.session && req.session.username) {
    next();
  } else {
    res.redirect("/login?timeout=true");
  }
}

function isValidIsraeliID(id) {
  id = String(id).trim();
  if (id.length > 9 || id.length < 5 || isNaN(id)) return false;
  id = id.padStart(9, "0");
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    let num = Number(id[i]) * (i % 2 === 0 ? 1 : 2);
    if (num > 9) num -= 9;
    sum += num;
  }
  return sum % 10 === 0;
}

// טעינת נהגים
const filePath = path.join(__dirname, "data", "drivers.json");
let driverData = {};

if (fs.existsSync(filePath)) {
  try {
    const content = fs.readFileSync(filePath, "utf-8").trim();
    driverData = content ? JSON.parse(content) : {};
  } catch (err) {
    console.error("❌ שגיאה בקריאת drivers.json:", err);
    driverData = {};
  }
} else {
  saveDrivers();
}

function saveDrivers() {
  if (!fs.existsSync(path.join(__dirname, "data"))) {
    fs.mkdirSync(path.join(__dirname, "data"));
  }
  console.log("שימור נתונים ב־drivers.json:", driverData); // לוג לפני שמירה
  fs.writeFileSync(filePath, JSON.stringify(driverData, null, 2), "utf-8");
  console.log("נתונים נשמרו ב־drivers.json");
}

const statsFile = path.join(__dirname, "logs", "passed-drivers.json");

app.post("/mark-statistics/:id", ensureLoggedIn, (req, res) => {
  const driverId = req.params.id;
  const driver = driverData[driverId];
  if (!driver || !driver.driverStatus) return res.sendStatus(400);

  const statsFile = path.join(__dirname, "logs", "passed-drivers.json");
  let data = [];

  if (fs.existsSync(statsFile)) {
    try {
      data = JSON.parse(fs.readFileSync(statsFile, "utf-8"));
    } catch (err) {
      console.error("שגיאה בקריאת passed-drivers.json:", err);
    }
  }

  // אם לנהג יש מספר תיאומים - שמור כל אחד בנפרד
  if (Array.isArray(driver.coordinations)) {
    driver.coordinations.forEach((coord) => {
      data.push({
        name: driver.name,
        idNumber: driver.idNumber,
        phone: driver.phone || driver.phoneNumber || "",
        employer: driver.employer || "",
        coordinationNumber: coord.coordinationNumber || "",
        goodsType: coord.goodsType || "",
        donorOrg: coord.donorOrg || "",
        passedAt: driver.passedAt || "",
      });
    });
  } else {
    // שמירe  רגילה (נהגים בלי מערך coordinations)
    data.push({
      name: driver.name,
      idNumber: driver.idNumber,
      phone: driver.phone || driver.phoneNumber || "",
      employer: driver.employer || "",
      coordinationNumber: driver.coordinationNumber || "",
      goodsType: driver.goodsType || "",
      donorOrg: driver.donorOrg || "",
      passedAt: driver.passedAt || "",
    });
  }

  fs.writeFileSync(statsFile, JSON.stringify(data, null, 2), "utf-8");
  console.log(`✅ נשמרו סטטיסטיקות ל־${driver.name}`);
  res.sendStatus(200);
});

// ----------------- נתיבים -----------------

// דף התחברות
app.get("/logout", (req, res) => {
  saveDrivers(); // 🟢 שומר לפני יציאה
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// דף בית
app.get("/", ensureLoggedIn, (req, res) => {
  const search = req.query.search || "";
  let results = Object.entries(driverData);

  if (search) {
    results = results.filter(
      ([id, driver]) =>
        driver.name.includes(search) || driver.idNumber.includes(search),
    );
  }

  res.render("drivers", { drivers: results, role: req.session.role });
});

// הוספת נהג ידנית
app.get("/add-driver", ensureLoggedIn, (req, res) => {
  if (!can(req.session.permissions, "add-driver")) {
    return res.status(403).send("אין הרשאה להוסיף נהגים");
  }

  res.render("add-driver", { errorMessage: null });
});

app.post("/add-driver", (req, res) => {
  const drivers = Object.values(readJSON("data/drivers.json"));

  const {
    name,
    idNumber,
    phone,
    employer,
    employerPhone,
    coordinationNumber = [],
    goodsType = [],
    palletCount = [],
    truckNumber = [],
    donorOrg = [],
    route = [], // ✅ נוספה תמיכה בשדה "נתיב"
  } = req.body;

  // בדיקת כפילות ת.ז
  const existingDriver = drivers.find((d) => d.idNumber === idNumber);
  if (existingDriver) {
    return res.status(400).send("נהג עם תעודת זהות זו כבר קיים.");
  }

  // הפיכת השדות למערך תיאומים כולל route
  const coordinations = coordinationNumber.map((num, i) => ({
    coordinationNumber: num || "",
    goodsType: goodsType[i] || "",
    palletCount: palletCount[i] || "",
    truckNumber: truckNumber[i] || "",
    donorOrg: donorOrg[i] || "",
    route: route[i] || "", // ✅ כאן נוסף השדה
    passed: false,
    passedAt: null,
    checkedBy: null,
  }));

  const newDriver = {
    name,
    idNumber,
    phone,
    employer,
    employerPhone,
    status: "מאושר",
    notes: [],
    hasBlock: false,
    image:
      "https://cdn.glitch.global/64a24585-7ccf-4cfb-bfc3-67e1b6c37fe4/%D7%90%D7%99%D7%A9%201.png?v=1748175811296",
    driverStatus: false,
    passedAt: null,
    coordinations,
  };

  const newDriverId = Date.now().toString();
  driverData[newDriverId] = newDriver;
  writeJSON("drivers.json", driverData);

  res.redirect(
    "/login?biometricSetup=true&username=" + encodeURIComponent(user.username),
  );
});

// דף פרטי נהג
app.get("/driver/:id", ensureLoggedIn, (req, res) => {
  const driverId = req.params.id;
  const driver = driverData[driverId];

  if (!driver) {
    return res.status(404).send("Driver not found");
  }

  const coordinationData = {
    coordinationNumber: driver.coordinationNumber || "לנהג אין תיאום להיום",
    goodsType: driver.goodsType || "לא צויין",
    palletCount: driver.palletCount || "לא צויין",
  };

  const isAdmin = req.session.role === "admin";
  res.render("driver", {
    driverId,
    driver,
    coordinationData,
    isAdmin,
    role: req.session.role || "visitor", // ✅ חובה!
  });
});

// עריכת נהג
app.get("/edit-driver/:id", ensureLoggedIn, (req, res) => {
  if (!can(req.session.permissions, "edit-driver")) {
    return res.status(403).send("אין הרשאה לערוך נהגים");
  }
  const driverId = req.params.id;
  const driver = driverData[driverId];
  if (!driver) return res.status(404).send("Driver not found");

  res.render("edit-driver", { driverId, driver, errorMessage: null });
});

app.post("/edit-driver/:id", ensureLoggedIn, (req, res) => {
  if (!can(req.session.permissions, "edit-driver")) {
    return res.status(403).send("אין הרשאה לערוך נהגים");
  }

  const driverId = req.params.id;
  const { name, idNumber, phone, status, employerPhone, employer } = req.body;

  if (!driverData[driverId]) {
    return res.status(404).send("Driver not found");
  }

  if (!isValidIsraeliID(idNumber)) {
    return res.render("edit-driver", {
      driverId,
      driver: driverData[driverId],
      errorMessage: "תעודת זהות אינה תקינה.",
    });
  }

  const duplicate = Object.entries(driverData).some(
    ([id, driver]) => driver.idNumber === idNumber && id !== driverId,
  );
  if (duplicate) {
    return res.render("edit-driver", {
      driverId,
      driver: driverData[driverId],
      errorMessage: "תעודת זהות כבר קיימת במערכת.",
    });
  }

  // פונקציה עוזרת להבטיח מערך תקין
  function toArray(val) {
    return Array.isArray(val) ? val : val ? [val] : [];
  }

  const coordinationNumbers = toArray(req.body.coordinationNumber);
  const goodsTypes = toArray(req.body.goodsType);
  const palletCounts = toArray(req.body.palletCount);
  const donorOrgs = toArray(req.body.donorOrg);
  const truckNumbers = toArray(req.body.truckNumber);
  const routes = toArray(req.body.route); // ✅ נוספה תמיכה בנתיב

  let currentEditableIndex = 0;

  driverData[driverId].coordinations = (
    driverData[driverId].coordinations || []
  ).map((coord) => {
    if (coord.passed === true) {
      return coord; // לא נוגעים בתיאום שעבר
    }

    const updatedCoord = {
      ...coord,
      coordinationNumber: coordinationNumbers[currentEditableIndex] || "",
      goodsType: goodsTypes[currentEditableIndex] || "",
      palletCount: palletCounts[currentEditableIndex] || "",
      donorOrg: donorOrgs[currentEditableIndex] || "",
      truckNumber: truckNumbers[currentEditableIndex] || "",
      route: routes[currentEditableIndex] || "", // ✅ נתיב
    };

    currentEditableIndex++;
    return updatedCoord;
  });

  driverData[driverId] = {
    ...driverData[driverId],
    name,
    idNumber,
    phone,
    status,
    employerPhone,
    employer,
  };

  saveDrivers();
  res.redirect(`/driver/${driverId}`);
});

app.post(
  "/transfer-coordination/:driverId/:coordIndex",
  ensureLoggedIn,
  (req, res) => {
    try {
      const sourceDriverId = req.params.driverId;
      const coordIndex = parseInt(req.params.coordIndex);
      const targetIdNumber = (req.body.targetIdNumber || "").trim();

      if (!driverData[sourceDriverId]) {
        console.error("❌ נהג מקור לא נמצא");
        return res.status(400).send("נהג המקור לא קיים");
      }

      const sourceDriver = driverData[sourceDriverId];

      if (!Array.isArray(sourceDriver.coordinations)) {
        console.error("❌ לנהג אין מערך תיאומים");
        return res.status(400).send("אין לנהג תיאומים להעברה");
      }

      if (!sourceDriver.coordinations[coordIndex]) {
        console.error("❌ אינדקס תיאום לא חוקי");
        return res.status(400).send("תיאום לא קיים");
      }

      const coordination = sourceDriver.coordinations[coordIndex];

      if (coordination.passed) {
        console.error("❌ ניסיון להעביר תיאום שסומן כבר");
        return res.status(400).send("לא ניתן להעביר תיאום שכבר נבדק");
      }

      const targetEntry = Object.entries(driverData).find(
        ([_, d]) => d.idNumber === targetIdNumber,
      );

      if (!targetEntry) {
        console.error('❌ נהג יעד לא נמצא לפי ת"ז:', targetIdNumber);
        return res.status(404).send("נהג היעד לא נמצא");
      }

      const [targetDriverId, targetDriver] = targetEntry;

      if (!Array.isArray(targetDriver.coordinations)) {
        targetDriver.coordinations = [];
      }

      // העבר את התיאום
      targetDriver.coordinations.push(coordination);
      sourceDriver.coordinations.splice(coordIndex, 1);

      saveDrivers();
      console.log(
        `🔄 העברה: מתיאום אצל ${sourceDriver.name} אל ${targetDriver.name}`,
      );
      res.redirect(`/driver/${sourceDriverId}`);
    } catch (err) {
      console.error("💥 שגיאה כללית בהעברת תיאום:", err);
      res.status(500).send("שגיאת שרת כללית");
    }
  },
);

// מחיקת נהג
app.post("/delete-driver/:id", ensureLoggedIn, (req, res) => {
  if (!can(req.session.permissions, "delete-driver")) {
    return res.status(403).send("אין הרשאה למחוק נהגים");
  }

  const driverId = req.params.id;
  if (!driverData[driverId]) return res.status(404).send("Driver not found");

  delete driverData[driverId];
  saveDrivers();
  res.redirect("/");
});

// העלאת תמונה לנהג
app.post(
  "/upload-image/:id",
  ensureLoggedIn,
  upload.single("driverImage"),
  (req, res) => {
    const driverId = req.params.id;

    if (!driverData[driverId]) return res.status(404).send("Driver not found");

    if (req.file) {
      driverData[driverId].image = "/uploads/" + req.file.filename;
      saveDrivers();
    }

    res.redirect(`/driver/${driverId}`);
  },
);

// שמירת צ'קבוקס "עבר בקרה"
app.post("/save-checkbox/:id", ensureLoggedIn, (req, res) => {
  const driverId = req.params.id;
  const driverStatus = req.body.driverStatus === "on";

  if (!driverData[driverId]) return res.status(404).send("Driver not found");
  if (!can(req.session.permissions, "toggle-status")) {
    return res.status(403).send("אין הרשאה לסמן מעבר בקרה");
  }

  driverData[driverId].driverStatus = driverStatus;
  driverData[driverId].passedAt = driverStatus
    ? new Date().toLocaleTimeString("he-IL", {
        timeZone: "Asia/Jerusalem",
        hour: "2-digit",
        minute: "2-digit",
      })
    : null;

  saveDrivers();
  res.redirect(`/driver/${driverId}`);
});

// דף העלאת קובץ תיאומים
app.get("/upload-coordinations", ensureLoggedIn, (req, res) => {
  console.log("👀 session.permissions:", req.session.permissions);
  if (!can(req.session.permissions, "upload-coordinations")) {
    return res.status(403).send("אין הרשאה להעלות קובץ תיאומים");
  }
  res.render("upload-coordinations");
});

// ✅ גרסה נקייה ומתוקנת של הקוד לעיבוד קובץ תיאומים
// ללא כפילויות, כולל תמיכה בריבוי תיאומים לכל נהג
// יש למקם את הקוד הזה במקום הנתיב הישן של POST /upload-coordinations

app.post(
  "/upload-coordinations",
  ensureLoggedIn,
  upload.single("coordinationsFile"),
  (req, res) => {
    if (!can(req.session.permissions, "upload-coordinations")) {
      return res.status(403).send("אין הרשאה להעלות קובץ");
    }

    if (!req.file) {
      return res.status(400).send("לא הועלה קובץ");
    }

    const fileContent = fs.readFileSync(req.file.path, "utf-8");
    parseCSV(fileContent, { columns: true, trim: true }, (err, records) => {
      if (err || !records || records.length === 0) {
        return res.status(400).send("⚠️ הקובץ ריק או לא תקין");
      }

      const blacklistPath = path.join(__dirname, "data", "blacklist.json");
      const blacklist = fs.existsSync(blacklistPath)
        ? JSON.parse(fs.readFileSync(blacklistPath, "utf-8"))
        : [];

      const groupedById = {};
      const blacklistedDrivers = [];

      records.forEach((record) => {
        const idNumber = (record["תעודת זהות"] || "").trim();
        if (!idNumber) return;

        const isBlacklisted = blacklist.some(
          (item) => idSimilarity(item.idNumber, idNumber) >= 0.9,
        );

        const coordination = {
          coordinationNumber: record["מספר תיאום"] || "",
          goodsType: record["סוג סחורה"] || "",
          palletCount: record["מספר משטחים"] || "",
          truckNumber: record["מספר משאית"] || "",
          donorOrg: record["ארגון תורם"] || "",
          route: record["נתיב"] || "", // ✅ הוספנו את השדה החדש
          passed: false,
          passedAt: null,
        };

        if (!groupedById[idNumber]) {
          groupedById[idNumber] = {
            idNumber,
            name: record["שם נהג"] || "",
            phone: record["טלפון נהג"] || "",
            employer: record["שם מעסיק"] || "",
            employerPhone: record["טלפון מעסיק"] || "",
            status: isBlacklisted ? "מנוע" : "מאושר",
            image:
              "https://cdn.glitch.global/64a24585-7ccf-4cfb-bfc3-67e1b6c37fe4/%D7%90%D7%99%D7%A9%201.png?v=1748175811296",
            driverStatus: false,
            passedAt: null,
            events: "",
            coordinations: [coordination],
          };

          if (isBlacklisted) {
            blacklistedDrivers.push({
              "שם נהג": groupedById[idNumber].name,
              "תעודת זהות": idNumber,
            });
          }
        } else {
          groupedById[idNumber].coordinations.push(coordination);
        }
      });

      // אם יש מנועים → עצור והצג אזהרה
      if (blacklistedDrivers.length > 0) {
        const tempPath = path.join(__dirname, "temp");
        if (!fs.existsSync(tempPath)) fs.mkdirSync(tempPath);

        const filePath = path.join(tempPath, `coord_${Date.now()}.json`);
        fs.writeFileSync(
          filePath,
          JSON.stringify(groupedById, null, 2),
          "utf-8",
        );

        return res.render("blacklist-warning", {
          flagged: blacklistedDrivers,
          filePath,
        });
      }

      // שמירה רגילה כי אין מנועים
      for (const idNumber in groupedById) {
        const driverInfo = groupedById[idNumber];
        const existingEntry = Object.entries(driverData).find(
          ([_, d]) => d.idNumber === idNumber,
        );

        if (existingEntry) {
          const [driverId, driver] = existingEntry;
          driverData[driverId] = {
            ...driver,
            ...driverInfo,
            status: driverInfo.status || driver.status || "מאושר", // 🟢 חובה לשמירה תקינה
          };
          console.log(`עודכן נהג קיים: ${driver.name}`);
        } else {
          const newId = Date.now() + Math.floor(Math.random() * 1000);
          driverData[newId] = {
            ...driverInfo,
            status: driverInfo.status || "מאושר", // 🟢 גם כאן לשם ודאות
          };
          console.log(`נוסף נהג חדש: ${driverInfo.name}`);
        }
      }

      saveDrivers();
      res.render("success", { message: "✅ תיאומים סונכרנו בהצלחה!" });
    });
  },
);

const moment = require("moment");

app.post(
  "/upload-image/:id",
  ensureLoggedIn,
  upload.single("driverImage"),
  (req, res) => {
    const driverId = req.params.id;
    if (!driverData[driverId]) return res.status(404).send("Driver not found");

    if (req.file) {
      driverData[driverId].image = req.file.filename; // לא כולל /uploads/
      saveDrivers();
    }

    res.redirect(`/driver/${driverId}`);
  },
);
app.post("/update-yuval", (req, res) => {
  const { key, value } = req.body;

  if (!key) {
    console.log("⛔ אין מפתח תקף");
    return res.sendStatus(400);
  }

  console.log("🚨 קיבלתי בקשה ל־/update-yuval");
  console.log("🔑 key:", key);
  console.log("✅ value:", value);

  const yuvalPath = path.join(__dirname, "data", "yuval.json");
  let yuvalData = {};

  if (fs.existsSync(yuvalPath)) {
    try {
      yuvalData = JSON.parse(fs.readFileSync(yuvalPath, "utf-8"));
    } catch (e) {
      console.error("⚠ שגיאה ב־yuval.json:", e);
    }
  }

  yuvalData[key] = value;

  fs.writeFileSync(yuvalPath, JSON.stringify(yuvalData, null, 2), "utf-8");
  console.log(`💾 נשמר ב־yuval.json: ${key} = ${value}`);
  res.sendStatus(200);
});

// התנתקות
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/manage-users", ensureLoggedIn, (req, res) => {
  console.log("🚨 הרשאות:", req.session.permissions);
  if (!can(req.session.permissions, "manage-users")) {
    return res.status(403).send("אין הרשאה לניהול משתמשים");
  }

  const users = fs.existsSync(usersPath)
    ? JSON.parse(fs.readFileSync(usersPath, "utf8"))
    : {};

  res.render("manage-users", {
    users,
    permissions: req.session.permissions || [],
  });
});

app.post("/delete-user", ensureLoggedIn, (req, res) => {
  if (req.session.role !== "admin") {
    return res.status(403).send("אין הרשאה למחוק משתמשים");
  }

  const usernameToDelete = req.body.username
    ? req.body.username.trim().toLowerCase()
    : "";

  if (!usernameToDelete || usernameToDelete === "barnoy") {
    return res.send("לא ניתן למחוק את המשתמש barnoy");
  }

  if (!fs.existsSync(usersPath)) {
    return res.status(500).send("קובץ users.json לא נמצא");
  }

  const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));

  if (!users[usernameToDelete]) {
    return res.send("המשתמש לא קיים");
  }

  delete users[usernameToDelete];
  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2), "utf8");

  console.log(`🗑️ המשתמש ${usernameToDelete} נמחק`);
  res.redirect("/manage-users");
});

// קובץ JSON שישמור את הנתונים עבור "הוזן ביובל"
const yuvalPath = path.join(__dirname, "data", "yuval.json");
let yuvalData = {};

// טעינת הקובץ הקיים אם קיים, או יצירת חדש
if (fs.existsSync(yuvalPath)) {
  try {
    const raw = fs.readFileSync(yuvalPath, "utf-8").trim();
    yuvalData = raw ? JSON.parse(raw) : {};
  } catch (err) {
    console.error("❌ שגיאה בקריאת yuval.json:", err);
    yuvalData = {};
  }
} else {
  fs.writeFileSync(yuvalPath, "{}", "utf-8");
}

// פונקציה לשמירת הנתונים
function saveYuvalData() {
  fs.writeFileSync(yuvalPath, JSON.stringify(yuvalData, null, 2), "utf-8");
}

app.post("/add-user", async (req, res) => {
  if (!can(req.session.permissions, "manage-users")) {
    return res.status(403).send("אין הרשאה להוסיף משתמשים");
  }

  const { username, password, confirmPassword, role } = req.body;
  const permissionsArray = Array.isArray(req.body.permissions)
    ? req.body.permissions
    : [req.body.permissions].filter(Boolean);

  const moment = require("moment"); // אם עדיין לא הוספת למעלה
  const SECRET_TOKEN = "xk98aZ73B7fsG1qW2s9n"; // אותו טוקן שהשתמשת בו

  app.get(`/cron/check-flagged-drivers/${SECRET_TOKEN}`, (req, res) => {
    const today = moment().format("YYYY-MM-DD");

    const flaggedDrivers = Object.entries(driverData).filter(([id, driver]) => {
      return driver.coordinationDate === today && driver.driverStatus !== true;
    });

    if (flaggedDrivers.length > 0) {
      const list = flaggedDrivers
        .map(([id, d]) => `• ${d.name} (${d.idNumber})`)
        .join("\n");
      console.log(`🔔 התראה: נהגים שלא עברו בקרה עד 12:00:\n${list}`);
      res.send(`נמצאו ${flaggedDrivers.length} נהגים שלא עברו בקרה:\n${list}`);
    } else {
      console.log("✅ כל הנהגים עם תיאום עברו בקרה עד 12:00");
      res.send("כל הנהגים עברו בקרה.");
    }
  });

  const cleanUsername = username.trim().toLowerCase();

  if (!cleanUsername || !password || !confirmPassword || !role) {
    return res.render("add-user", { errorMessage: "נא למלא את כל השדות" });
  }

  if (password !== confirmPassword) {
    return res.render("add-user", { errorMessage: "הסיסמאות אינן תואמות" });
  }

  const users = fs.existsSync(usersPath)
    ? JSON.parse(fs.readFileSync(usersPath, "utf8"))
    : {};

  if (users[cleanUsername]) {
    return res.render("add-user", { errorMessage: "שם המשתמש כבר קיים" });
  }

  const passwordHash = await bcrypt.hash(password.trim(), 12);

  users[cleanUsername] = {
    username: cleanUsername,
    passwordHash,
    role,
    permissions: permissionsArray,
  };

  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2), "utf8");
  console.log(`👤 משתמש חדש נוסף: ${cleanUsername} (${role})`);

  res.redirect("/manage-users");
});
app.get("/add-user", ensureLoggedIn, (req, res) => {
  if (!can(req.session.permissions, "manage-users")) {
    return res.status(403).send("אין הרשאה לגשת לעמוד זה");
  }

  res.render("add-user", {
    errorMessage: null,
    userPermissions: req.session.permissions, // ✅ זה מה שחסר
  });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log("👉 קלט מהטופס:", username, password);

  const now = Date.now();

  // יצירת רשומה ראשונית אם אין
  if (!loginAttempts[username]) {
    loginAttempts[username] = { fails: 0, lastAttempt: 0 };
  }

  const userAttempt = loginAttempts[username];

  // חסימה ל-10 דקות אחרי 5 ניסיונות כושלים
  const blockDuration = 10 * 60 * 1000;
  if (userAttempt.fails >= 5 && now - userAttempt.lastAttempt < blockDuration) {
    console.log("🚫 חשבון חסום זמנית בגלל ניסיונות כושלים");
    return res.send(
      "⛔️ חשבונך נחסם זמנית לאחר מספר ניסיונות כושלים. נסה שוב בעוד כמה דקות.",
    );
  }

  if (!fs.existsSync(usersPath)) {
    console.log("❌ קובץ users.json לא נמצא");
    return res.status(500).send("קובץ משתמשים לא קיים");
  }

  const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  const user = users[username];

  if (!user) {
    console.log("❌ שם משתמש לא נמצא בקובץ");

    loginAttempts[username].fails += 1;
    loginAttempts[username].lastAttempt = now;
    saveLoginAttempts();

    return res.send("שם משתמש או סיסמה שגויים");
  }

  try {
    const result = await bcrypt.compare(password.trim(), user.passwordHash);

    if (!result) {
      console.log("❌ סיסמה לא תואמת");

      loginAttempts[username].fails += 1;
      loginAttempts[username].lastAttempt = now;
      saveLoginAttempts();

      return res.send("שם משתמש או סיסמה שגויים");
    }

    console.log("✅ התחברות הצליחה!");

    // איפוס ניסיונות לאחר הצלחה
    loginAttempts[username] = { fails: 0, lastAttempt: 0 };
    saveLoginAttempts();

    req.session.username = user.username;
    req.session.role = user.role;
    req.session.permissions = user.permissions || permissions[user.role] || [];
    req.session.fullName = user.fullName || user.username; // ✅ הוספה חשובה
    console.log("🔐 הרשאות נטענו:", req.session.permissions);

    const now = new Date();
    const lastChange = new Date(user.lastPasswordChange || 0);
    const diffDays = (now - lastChange) / (1000 * 60 * 60 * 24);

    if (user.mustChangePassword || diffDays >= 14) {
      req.session.tempUser = username;
      return res.render("login", { timeout: false, mustChange: true });
    }

    res.redirect("/");
  } catch (err) {
    console.error("⚠ שגיאה בבדיקת סיסמה:", err);
    res.status(500).send("שם משתמש או סיסמה שגויים");
  }
});
app.get("/reset-login-attempts", ensureLoggedIn, (req, res) => {
  if (req.session.role !== "admin") {
    return res.status(403).send("אין הרשאה לאפס ניסיונות התחברות");
  }

  loginAttempts = {};
  saveLoginAttempts();
  console.log("🔁 כל ניסיונות ההתחברות אופסו על ידי admin");

  res.send("✅ כל ניסיונות ההתחברות אופסו בהצלחה!");
});
app.get("/edit-password/:username", ensureLoggedIn, (req, res) => {
  if (req.session.role !== "admin") return res.status(403).send("אין הרשאה");

  const username = req.params.username;
  res.render("edit-password", { username, errorMessage: null });
});
app.post("/edit-password/:username", async (req, res) => {
  if (req.session.role !== "admin") return res.status(403).send("אין הרשאה");

  const username = req.params.username;
  const { newPassword, confirmPassword } = req.body;

  if (!newPassword || newPassword.length < 4) {
    return res.render("edit-password", {
      username,
      errorMessage: "הסיסמה חייבת להכיל לפחות 4 תווים",
    });
  }

  if (newPassword !== confirmPassword) {
    return res.render("edit-password", {
      username,
      errorMessage: "הסיסמאות אינן תואמות",
    });
  }

  const users = fs.existsSync(usersPath)
    ? JSON.parse(fs.readFileSync(usersPath, "utf8"))
    : {};

  if (!users[username]) {
    return res.send("המשתמש לא נמצא");
  }

  const passwordHash = await bcrypt.hash(newPassword, 12);
  users[username].passwordHash = passwordHash;

  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2), "utf8");
  console.log(`🔑 הסיסמה של ${username} שונתה`);

  res.redirect("/manage-users");
});
app.get("/reset-coordinations", (req, res) => {
  for (let id in driverData) {
    driverData[id].coordinationNumber = "לא קיים תיאום להיום";
    driverData[id].goodsType = "";
    driverData[id].palletCount = "";
    driverData[id].driverStatus = false;
    driverData[id].passedAt = null;
  }

  saveDrivers();
  console.log("🕛 RESET דרך cron החיצוני");
  res.send("✅ RESET מהצלחה דרך cron");
}); // ← סוגר נכון את הנתיב הזה

app.get("/cron-reset", (req, res) => {
  const secret = req.query.key;
  if (secret !== "xk98aZ73B7fsG1qW2s9n") {
    return res.status(403).send("⛔ לא מורשה");
  }
  // איפוס פרטי התיאום
  for (let id in driverData) {
    driverData[id].coordinationNumber = "לא קיים תיאום להיום";
    driverData[id].goodsType = "";
    driverData[id].palletCount = "";
    driverData[id].driverStatus = false;
    driverData[id].passedAt = null;
    driverData[id].truckNumber = null;
    driverData[id].donorOrg = null;
    driverData[id].driverStatus = false; // איפוס הצ'קבוקס
    driverData[id].passedAt = null;
  }
  saveDrivers();
  console.log("✅ איפוס תיאומים דרך cron-reset (עם מפתח)");
  res.send("תיאומים אופסו בהצלחה דרך cron-reset");
});

app.post(
  "/update-coordination-status/:id/:index",
  ensureLoggedIn,
  (req, res) => {
    const moment = require("moment-timezone");

    const driverId = req.params.id;
    const index = parseInt(req.params.index);

    if (!can(req.session.permissions, "toggle-status")) {
      return res.status(403).send("אין הרשאה");
    }

    if (
      !driverData[driverId] ||
      !Array.isArray(driverData[driverId].coordinations)
    ) {
      return res.status(404).send("נהג לא נמצא או אין לו תיאומים");
    }

    const coord = driverData[driverId].coordinations[index];
    if (!coord) return res.status(400).send("תיאום לא קיים");

    const isChecked = req.body.checked === "on";
    coord.passed = isChecked;

    if (isChecked) {
      const nowJerusalem = moment().tz("Asia/Jerusalem");
      coord.passedAt = nowJerusalem.format("HH:mm");
      coord.checkedBy = req.session.fullName || req.session.username; // ✅ שם הבודק
    } else {
      coord.passedAt = null;
      coord.checkedBy = null;
    }

    saveDrivers();
    res.redirect(`/driver/${driverId}`);
  },
);

app.get("/export-csv", (req, res) => {
  const driversPath = "/data/drivers.json";

  if (!fs.existsSync(driversPath)) {
    return res.status(404).send("קובץ drivers.json לא קיים.");
  }

  const rawData = JSON.parse(fs.readFileSync(driversPath, "utf-8"));
  const passedDrivers = [];

  Object.entries(rawData).forEach(([id, driver]) => {
    if (Array.isArray(driver.coordinations)) {
      driver.coordinations.forEach((coord) => {
        if (coord.passed === true) {
          passedDrivers.push({
            name: driver.name,
            idNumber: driver.idNumber,
            phone: driver.phone || driver.phoneNumber || "",
            employer: driver.employer || "",
            coordinationNumber: coord.coordinationNumber || "",
            goodsType: coord.goodsType || "",
            donorOrg: coord.donorOrg || "",
            passedAt: coord.passedAt || "",
          });
        }
      });
    } else if (driver.driverStatus === true) {
      passedDrivers.push({
        name: driver.name,
        idNumber: driver.idNumber,
        phone: driver.phone || driver.phoneNumber || "",
        employer: driver.employer || "",
        coordinationNumber: driver.coordinationNumber || "",
        goodsType: driver.goodsType || "",
        donorOrg: driver.donorOrg || "",
        passedAt: driver.passedAt || "",
      });
    }
  });

  const cleanDrivers = passedDrivers.filter(
    (d) => d && Object.keys(d).length > 0,
  );
  if (cleanDrivers.length === 0) {
    return res.status(400).send("⚠️ אין נתונים זמינים לייצוא.");
  }

  const fields = [
    "name",
    "idNumber",
    "phone",
    "employer",
    "coordinationNumber",
    "goodsType",
    "donorOrg",
    "passedAt",
  ];
  const opts = { fields, encoding: "utf-8" };

  try {
    const csv = parse(cleanDrivers, opts);
    res.setHeader("Content-Disposition", "attachment; filename=statistics.csv");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.send("\uFEFF" + csv); // BOM לתמיכה בעברית
  } catch (err) {
    console.error("שגיאה בהמרת CSV:", err);
    res.status(500).send("שגיאה בהמרת הנתונים ל־CSV");
  }
});

app.post("/update-yuval/:key", ensureLoggedIn, (req, res) => {
  const key = req.params.key; // לדוגמה: תעודת זהות + אינדקס
  const isChecked = req.body.yuval === "on";

  if (!yuvalData) yuvalData = {};
  yuvalData[key] = isChecked;

  saveYuvalData();
  res.sendStatus(200);
});

app.get("/driver/:id/coord-gatepass/:index", ensureLoggedIn, (req, res) => {
  const driverId = req.params.id;
  const index = parseInt(req.params.index);

  const driver = driverData[driverId];
  if (!driver) return res.status(404).send("נהג לא נמצא");

  if (!Array.isArray(driver.coordinations) || !driver.coordinations[index]) {
    return res.status(400).send("תיאום לא קיים");
  }

  const coordination = driver.coordinations[index];

  if (!coordination.passed) {
    coordination.passed = true;
    coordination.passedAt = moment
      .tz(new Date(), "Asia/Jerusalem")
      .format("HH:mm");
    coordination.checkedBy = req.session.username || "לא ידוע";
  }

  coordination.gatePassPrinted = true;

  saveDrivers();

  res.render("gatepass", {
    driver,
    coordination,
  });
});

app.post(
  "/update-coordination-status/:id/:index",
  ensureLoggedIn,
  (req, res) => {
    const moment = require("moment-timezone");

    const driverId = req.params.id;
    const index = parseInt(req.params.index);

    if (!can(req.session.permissions, "toggle-status")) {
      return res.status(403).send("אין הרשאה");
    }

    if (
      !driverData[driverId] ||
      !Array.isArray(driverData[driverId].coordinations)
    ) {
      return res.status(404).send("נהג לא נמצא או אין לו תיאומים");
    }

    const coord = driverData[driverId].coordinations[index];
    if (!coord) return res.status(400).send("תיאום לא קיים");

    const isChecked = req.body.checked === "on";
    coord.passed = isChecked;

    if (isChecked) {
      const nowJerusalem = moment().tz("Asia/Jerusalem");
      coord.passedAt = nowJerusalem.format("HH:mm");
      coord.checkedBy = req.session.fullName || req.session.username; // ✅ כאן נשמר השם המלא
    } else {
      coord.passedAt = null;
      coord.checkedBy = null;
    }

    saveDrivers();
    res.redirect(`/driver/${driverId}`);
  },
);
// הוספת תיאום חדש
app.post("/driver/:id/add-coordination", ensureLoggedIn, (req, res) => {
  // בדיקה אם למשתמש יש הרשאה להוסיף תיאום
  if (!can(req.session.permissions, "add-coordination")) {
    return res.status(403).send("אין לך הרשאה להוסיף תיאום");
  }

  const driverId = req.params.id;
  if (!driverData[driverId]) return res.status(404).send("נהג לא נמצא");

  const newCoordination = {
    coordinationNumber: req.body.coordinationNumber || "",
    goodsType: req.body.goodsType || "",
    palletCount: req.body.palletCount || "",
    truckNumber: req.body.truckNumber || "",
    donorOrg: req.body.donorOrg || "",
    route: req.body.route || "", // ✅ הוספה חדשה
    passed: false,
    passedAt: null,
    checkedBy: null,
  };

  driverData[driverId].coordinations = driverData[driverId].coordinations || [];
  driverData[driverId].coordinations.push(newCoordination);
  saveDrivers();
  res.redirect(`/driver/${driverId}`);
});

app.get("/driver/:id/add-coordination", ensureLoggedIn, (req, res) => {
  const driverId = req.params.id;
  const driver = driverData[driverId];

  if (!driver) return res.status(404).send("Driver not found");

  res.render("add-coordination", {
    driverId,
    driver,
    errorMessage: null,
  });
});

// הסרת תיאום לפי אינדקס
app.post(
  "/driver/:id/delete-coordination/:index",
  ensureLoggedIn,
  (req, res) => {
    const driverId = req.params.id;
    const index = parseInt(req.params.index);

    if (
      !driverData[driverId] ||
      !Array.isArray(driverData[driverId].coordinations)
    ) {
      return res.status(404).send("Driver not found or no coordinations");
    }

    driverData[driverId].coordinations.splice(index, 1);
    saveDrivers();
    res.redirect(`/driver/${driverId}`);
  },
);

app.get("/drivers-list", ensureLoggedIn, (req, res) => {
  const list = Object.values(driverData).map((driver) => ({
    name: driver.name,
    idNumber: driver.idNumber,
  }));
  res.json(list);
});

app.post("/force-upload-coordinations", ensureLoggedIn, (req, res) => {
  const filePath = req.body.filePath;
  if (!filePath || !fs.existsSync(filePath)) {
    return res.status(400).send("⚠️ הקובץ הזמני לא נמצא");
  }

  const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));

  for (const idNumber in data) {
    const driverInfo = data[idNumber];
    const existingEntry = Object.entries(driverData).find(
      ([_, d]) => d.idNumber === idNumber,
    );

    if (existingEntry) {
      const [driverId, driver] = existingEntry;
      driverData[driverId] = { ...driver, ...driverInfo };
      console.log(`🔁 עודכן נהג קיים: ${driver.name}`);
    } else {
      const newId = Date.now() + Math.floor(Math.random() * 1000);
      driverData[newId] = driverInfo;
      console.log(`➕ נוסף נהג חדש: ${driverInfo.name}`);
    }
  }

  saveDrivers();

  // מחיקת הקובץ הזמני לאחר השימוש
  fs.unlinkSync(filePath);

  res.render("success", { message: "✅ הקובץ הועלה למרות מנועים" });
});
app.post("/reject-driver", ensureLoggedIn, (req, res) => {
  const { driverId, coordinationNumber, reason } = req.body;
  const drivers = readJSON("./drivers.json");

  const driver = drivers[driverId];
  if (!driver || !Array.isArray(driver.coordinations)) {
    return res.status(404).send("❌ נהג לא נמצא או אין לו תיאומים");
  }

  const coord = driver.coordinations.find(
    (c) => c.coordinationNumber === coordinationNumber,
  );

  if (!coord) {
    return res.status(404).send("❌ תיאום לא נמצא אצל הנהג");
  }

  if (!coord.passed) {
    return res.status(400).send("❌ ניתן לסרב רק לתיאום שעבר בקרה.");
  }

  coord.rejected = true;
  coord.rejectionReason = reason;
  coord.rejectedAt = new Date().toLocaleString("he-IL", {
    timeZone: "Asia/Jerusalem",
  });

  writeJSON("./drivers.json", drivers);
  res.redirect(`/driver/${driverId}`);
});

app.get("/reject-driver-form", ensureLoggedIn, (req, res) => {
  const { coordinationNumber } = req.query;
  const drivers = readJSON("./drivers.json");

  let found = null;

  for (const [driverId, driver] of Object.entries(drivers)) {
    if (driver.coordinations) {
      for (let c of driver.coordinations) {
        if (c.coordinationNumber === coordinationNumber) {
          found = { driverId, driver, coordination: c };
          break;
        }
      }
    }
    if (found) break;
  }

  if (!found) return res.status(404).send("Coordination not found");

  res.render("reject-driver", {
    driverId: found.driverId,
    coordinationNumber,
    driver: found.driver,
    coordination: found.coordination,
  });
});
app.get("/driver/:driverId", (req, res) => {
  const driverId = req.params.driverId;
  const drivers = readJSON("./drivers.json");
  const driver = drivers[driverId];

  if (!driver) {
    return res.status(404).send("Driver not found");
  }

  res.render("driver", { driver, driverId }); // ← חשוב! זה מה שמאפשר לך להשתמש ב־<%= driverId %>
});

app.post("/toggle-flag/:driverId", (req, res) => {
  const driverId = req.params.driverId;

  if (!driverData[driverId]) {
    return res.status(404).send("Driver not found");
  }

  driverData[driverId].flagged = !driverData[driverId].flagged;

  saveDrivers(); // שומר את driverData לקובץ
  res.redirect(`/driver/${driverId}`);
});
// שמירת סטטיסטיקות יומית לפי תאריך
app.get("/cron/save-statistics", (req, res) => {
  const secret = req.query.key;
  if (secret !== "xk98aZ73B7fsG1qW2s9n") {
    return res.status(403).send("⛔ לא מורשה");
  }

  const today = new Date().toISOString().split("T")[0];
  const statisticsDir = path.join(__dirname, "data", "statistics_logs");
  const filePath = path.join(statisticsDir, `${today}.json`);

  if (!fs.existsSync(statisticsDir)) {
    fs.mkdirSync(statisticsDir, { recursive: true });
  }
  // ✅ טען את yuval.json
  const yuvalPath = path.join(__dirname, "data", "yuval.json");
  const yuvalData = fs.existsSync(yuvalPath)
    ? JSON.parse(fs.readFileSync(yuvalPath, "utf-8"))
    : {};

  const passedDrivers = [];

  Object.entries(driverData).forEach(([id, driver]) => {
    if (Array.isArray(driver.coordinations)) {
      driver.coordinations.forEach((coord) => {
        if (coord.passed === true) {
          const key = `${driver.idNumber}-${coord.coordinationNumber}`;
          const yuval = yuvalData[key] === true;
          passedDrivers.push({
            name: driver.name,
            idNumber: driver.idNumber,
            phone: driver.phone || driver.phoneNumber || "",
            employer: driver.employer || "",
            status: driver.status || "",
            coordinationNumber: coord.coordinationNumber || "",
            goodsType: coord.goodsType || "",
            truckNumber: coord.truckNumber || "",
            donorOrg: coord.donorOrg || "",
            palletCount: coord.palletCount || "",
            route: coord.route || "",
            passed: coord.passed === true,
            passedAt: coord.passedAt || "",
            passedBy: coord.checkedBy || "",
            gatePassPrinted: coord.gatePassPrinted === true,
          });
        }
      });
    }
  });

  fs.writeFileSync(filePath, JSON.stringify(passedDrivers, null, 2), "utf-8");
  console.log(`📁 נשמרו ${passedDrivers.length} סטטיסטיקות עבור ${today}`);
  res.send(`✅ נשמרו ${passedDrivers.length} סטטיסטיקות עבור ${today}`);
});

app.get("/statistics/:date", ensureLoggedIn, (req, res) => {
  if (!can(req.session.permissions, "view-statistics")) {
    return res.status(403).send("אין הרשאה לצפייה בסטטיסטיקות");
  }

  const selectedDate = req.params.date;
  const filePath = path.join(
    __dirname,
    "data",
    "statistics_logs",
    `${selectedDate}.json`,
  );
  const yuvalPath = path.join(__dirname, "data", "yuval.json");

  const allStats = fs.existsSync(filePath)
    ? JSON.parse(fs.readFileSync(filePath, "utf-8"))
    : [];

  // כל הנהגים בקובץ הזה עברו תיאום, אין צורך בפילטר לפי status
  const filter = (req.query.q || "").toLowerCase();
  let passedDrivers = allStats.map((driver) => ({
    ...driver,
    phone: driver.phone || driver.phoneNumber || "—",
  }));

  if (filter) {
    passedDrivers = passedDrivers.filter((d) =>
      Object.values(d).some((val) => (val + "").toLowerCase().includes(filter)),
    );
  }

  // פילוח ארגונים
  const donorsSummary = {};
  passedDrivers.forEach((entry) => {
    const org = entry.donorOrg || "ללא שיוך";
    donorsSummary[org] = (donorsSummary[org] || 0) + 1;
  });

  let yuvalData = {};
  if (fs.existsSync(yuvalPath)) {
    try {
      yuvalData = JSON.parse(fs.readFileSync(yuvalPath, "utf-8"));
    } catch (err) {
      console.error("⚠️ שגיאה בקריאת yuval.json:", err);
    }
  }

  // אין לנו סירובים בקובץ היסטורי
  const refusedCoordinations = [];

  res.render("statistics", {
    passedDrivers,
    refusedCoordinations,
    count: passedDrivers.length,
    donorsSummary,
    today: selectedDate,
    yuvalData,
  });
});

app.get("/statistics", ensureLoggedIn, (req, res) => {
  if (!can(req.session.permissions, "view-statistics")) {
    return res.status(403).send("אין הרשאה לצפייה בסטטיסטיקות");
  }

  const selectedDate = req.query.date;
  const filter = (req.query.q || "").toLowerCase().trim();
  const yuvalPath = path.join(__dirname, "data", "yuval.json");

  let yuvalData = {};
  if (fs.existsSync(yuvalPath)) {
    try {
      yuvalData = JSON.parse(fs.readFileSync(yuvalPath, "utf-8"));
    } catch (err) {
      console.error("⚠️ שגיאה בקריאת yuval.json:", err);
    }
  }

  const passedDrivers = [];
  const refusedCoordinations = [];
  const donorsSummary = {};

  if (selectedDate) {
    // === סטטיסטיקה היסטורית ===
    const filePath = path.join(
      __dirname,
      "data",
      "statistics_logs",
      `${selectedDate}.json`,
    );
    if (fs.existsSync(filePath)) {
      try {
        const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
        data.forEach((driver) => {
          const match =
            !filter ||
            Object.values(driver).join(" ").toLowerCase().includes(filter);
          if (match) passedDrivers.push(driver);

          if (driver.reason) {
            refusedCoordinations.push({
              coordinationNumber: driver.coordinationNumber || "-",
              donorOrg: driver.donorOrg || "-",
              reason: driver.reason,
            });
          }

          if (driver.donorOrg) {
            donorsSummary[driver.donorOrg] =
              (donorsSummary[driver.donorOrg] || 0) + 1;
          }
        });
      } catch (err) {
        console.error("⚠️ שגיאה בקריאת קובץ סטטיסטיקה היסטורית:", err);
      }
    }
  } else {
    // === סטטיסטיקה חיה מהמערכת ===
    const statsPath = path.join(__dirname, "data", "drivers.json");
    let driverData = {};
    try {
      const fileContent = fs.readFileSync(statsPath, "utf-8").trim();
      driverData = fileContent ? JSON.parse(fileContent) : {};
    } catch (err) {
      console.error("⚠️ שגיאה בטעינת drivers.json:", err);
      driverData = {};
    }

    Object.entries(driverData).forEach(([driverId, driver]) => {
      if (Array.isArray(driver.coordinations)) {
        driver.coordinations.forEach((coord) => {
          if (coord.rejected === true) {
            refusedCoordinations.push({
              coordinationNumber: coord.coordinationNumber || "-",
              donorOrg: coord.donorOrg || "-",
              reason: coord.rejectionReason || "לא צוינה סיבה",
            });
          }

          if (coord.passed === true) {
            const match =
              !filter ||
              (driver.name && driver.name.toLowerCase().includes(filter)) ||
              (driver.idNumber && driver.idNumber.includes(filter)) ||
              (coord.goodsType &&
                coord.goodsType.toLowerCase().includes(filter)) ||
              (coord.truckNumber &&
                coord.truckNumber.toLowerCase().includes(filter)) ||
              (coord.donorOrg &&
                coord.donorOrg.toLowerCase().includes(filter)) ||
              (coord.route && coord.route.toLowerCase().includes(filter));

            if (match) {
              passedDrivers.push({
                name: driver.name,
                idNumber: driver.idNumber,
                phone: driver.phone || driver.phoneNumber || "",
                employer: driver.employer || "",
                truckNumber: coord.truckNumber || "",
                coordinationNumber: coord.coordinationNumber || "",
                goodsType: coord.goodsType || "",
                donorOrg: coord.donorOrg || "",
                palletCount: coord.palletCount || "",
                passedAt: coord.passedAt || "",
                gatePassPrinted: coord.gatePassPrinted === true,
                route: coord.route || "",
              });
            }

            if (coord.donorOrg) {
              donorsSummary[coord.donorOrg] =
                (donorsSummary[coord.donorOrg] || 0) + 1;
            }
          }
        });
      }
    });
  }

  res.render("statistics", {
    passedDrivers,
    refusedCoordinations,
    count: passedDrivers.length,
    donorsSummary,
    filter,
    selectedDate: selectedDate || "",
    today: !selectedDate,
    yuvalData: yuvalData || {},
  });
});

const statisticsLogsDir = path.join(__dirname, "data", "statistics_logs");

app.get("/search-statistics", ensureLoggedIn, (req, res) => {
  const query = (req.query.query || "").toLowerCase().trim();
  const statsDir = path.join(__dirname, "data", "statistics_logs");

  if (!query) return res.json([]);

  const matchedResults = [];

  if (!fs.existsSync(statsDir)) return res.json([]);

  const files = fs.readdirSync(statsDir).filter((f) => f.endsWith(".json"));

  for (const file of files) {
    const fullPath = path.join(statsDir, file);
    try {
      const data = JSON.parse(fs.readFileSync(fullPath, "utf-8"));
      data.forEach((driver) => {
        const values = Object.values(driver).join(" ").toLowerCase();
        if (values.includes(query)) {
          const dateFromFile = file.replace(".json", ""); // שלוף את התאריך משם הקובץ
          matchedResults.push({ ...driver, date: dateFromFile });
        }
      });
    } catch (err) {
      console.error(`⚠️ שגיאה בקובץ ${file}:`, err.message);
    }
  }

  res.json(matchedResults);
});
const USERS_PATH = path.join(__dirname, "data", "users.json");

app.get("/cron/require-password-change", (req, res) => {
  const secret = req.query.key;
  if (secret !== "Z3h8N1x2L9") return res.status(403).send("⛔ לא מורשה");

  const users = readJSON(USERS_PATH);
  const now = new Date();

  Object.keys(users).forEach((username) => {
    const user = users[username];
    const lastChange = new Date(user.lastPasswordChange || 0);
    const daysSince = (now - lastChange) / (1000 * 60 * 60 * 24);

    if (daysSince >= 14) {
      user.mustChangePassword = true;
    }
  });

  writeJSON(USERS_PATH, users);
  res.send("✔️ דרישת החלפת סיסמה עודכנה למשתמשים ישנים");
});

// GET - טופס שינוי סיסמה
app.get("/change-password", ensureLoggedIn, (req, res) => {
  if (!req.session.tempUser) {
    return res.redirect("/login");
  }
  res.render("change-password", {
    username: req.session.tempUser,
    errorMessage: null,
  });
});

app.post("/change-password", ensureLoggedIn, async (req, res) => {
  const { newPassword, confirmPassword } = req.body;
  const username = req.session.tempUser;

  if (!username) return res.redirect("/login");

  if (!newPassword || newPassword.length < 4) {
    return res.render("change-password", {
      username,
      errorMessage: "הסיסמה חייבת להכיל לפחות 4 תווים",
    });
  }

  if (newPassword !== confirmPassword) {
    return res.render("change-password", {
      username,
      errorMessage: "הסיסמאות אינן תואמות",
    });
  }

  // בדיקה - האם הסיסמה היא רק מספרים?
  if (/^\d+$/.test(newPassword)) {
    return res.render("change-password", {
      username,
      errorMessage: "הסיסמה לא יכולה להכיל רק מספרים בלבד",
    });
  }

  const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  if (!users[username]) {
    return res.redirect("/login");
  }

  // בדיקה אם הסיסמה החדשה זהה לסיסמה הישנה (השוואת hash עם bcrypt)
  const isSamePassword = await bcrypt.compare(
    newPassword.trim(),
    users[username].passwordHash,
  );
  if (isSamePassword) {
    return res.render("change-password", {
      username,
      errorMessage: "הסיסמה החדשה זהה לסיסמה הנוכחית. אנא בחר סיסמה שונה.",
    });
  }

  const passwordHash = await bcrypt.hash(newPassword.trim(), 12);
  users[username].passwordHash = passwordHash;
  users[username].mustChangePassword = false;
  users[username].lastPasswordChange = new Date().toISOString();

  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2), "utf8");

  // הסרת המשתנה הזמני session
  delete req.session.tempUser;

  // אחרי שמירת סיסמה חדשה בהצלחה
  res.redirect("/");
});

// 🧠 פונקציה לשמירת סטטיסטיקות לפי תיאומים שעברו בקרה
function saveDailyStatistics() {
  const fs = require("fs");
  const path = require("path");

  const driversPath = "/data/drivers.json";
  const statsDir = path.join(__dirname, "data", "statistics_logs");

  if (!fs.existsSync(driversPath)) return;
  if (!fs.existsSync(statsDir)) fs.mkdirSync(statsDir);

  const raw = fs.readFileSync(driversPath, "utf-8");
  const drivers = JSON.parse(raw);
  const passedStats = [];

  for (const [driverId, driver] of Object.entries(drivers)) {
    const name = driver.name || "";
    const idNumber = driver.idNumber || "";

    for (const coord of driver.coordinations || []) {
      if (coord.passed === true) {
        passedStats.push({
          driverId,
          name,
          idNumber,
          coordinationNumber: coord.coordinationNumber || "",
          goodsType: coord.goodsType || "",
          truckNumber: coord.truckNumber || "",
          donorOrg: coord.donorOrg || "",
          palletCount: coord.palletCount || "",
          route: coord.route || "",
          passed: true,
          passedAt: coord.passedAt || "",
          passedBy: coord.checkedBy || "",
          gatePassPrinted: coord.gatePassPrinted || false,
        });
      }
    }
  }

  const date = new Date().toISOString().split("T")[0]; // YYYY-MM-DD
  const outputFile = path.join(statsDir, `${date}.json`);
  fs.writeFileSync(outputFile, JSON.stringify(passedStats, null, 2), "utf-8");
}

// 📥 נתיב שמירה ידנית של סטטיסטיקות
app.get("/cron/save", (req, res) => {
  const key = req.query.key;
  if (key !== "x9a8273B785r1Giw9z9n") {
    return res.status(403).send("⛔ מפתח לא תקין");
  }

  saveDailyStatistics();
  res.send("✅ נשמרו סטטיסטיקות מהדרייברים");
});

app.get("/", (req, res) => {
  res.status(200).send("✅ Server is running");
});

// 🧹 נתיב איפוס drivers.json
app.get("/cron/reset", (req, res) => {
  const key = req.query.key;
  if (key !== "x9a8273B785r1Giw9z9n") {
    return res.status(403).send("⛔ מפתח לא תקין");
  }

  console.log("🧹 CRON: איפוס drivers.json");
  const driversPath = "/data/drivers.json";
  fs.writeFileSync(driversPath, "{}", "utf-8");
  res.send("✅ מאגר הנהגים אופס");
});

// דף התחברות (GET)
app.get("/login", (req, res) => {
  const timeout = req.query.timeout === "true";
  const mustChange = req.session.mustChangePassword === true; // או כל תנאי שהגדרת
  res.render("login", { timeout, mustChange });
});

app.post("/login-biometric", (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).send("חסר שם משתמש");
  }

  if (!fs.existsSync(usersPath)) {
    return res.status(500).send("קובץ משתמשים לא קיים");
  }

  const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  const user = users[username];

  if (!user) {
    return res.status(401).send("משתמש לא נמצא");
  }

  // יצירת session רגיל
  req.session.username = user.username;
  req.session.role = user.role;
  req.session.permissions = user.permissions || permissions[user.role] || [];
  req.session.fullName = user.fullName || user.username;

  console.log("🔐 התחברות ביומטרית הצליחה עבור:", username);
  res.status(200).send("OK");
});

app.get("/", (req, res) => {
  res.status(200).send("🟢 Server is running");
});

// 🔁 קרון שמירה ואיפוס דרך קריאה חיצונית
app.get("/cron/save-and-reset", (req, res) => {
  const key = req.query.key;
  if (key !== "xk98aZ73B7fsG1qW2s9n") {
    return res.status(403).send("Invalid key");
  }

  const driversPath = path.join(__dirname, "data", "drivers.json");
  const statsPath = path.join(__dirname, "data", "statistics_logs");
  const fs = require("fs");
  const date = new Date().toISOString().split("T")[0];
  const statsFile = path.join(statsPath, `${date}.json`);
  const drivers = readJSON(driversPath);

  const passedDrivers = [];
  for (const driverId in drivers) {
    const driver = drivers[driverId];
    if (Array.isArray(driver.coordinations)) {
      driver.coordinations.forEach((coord, index) => {
        if (coord.passed) {
          passedDrivers.push({
            ...coord,
            driverId,
            name: driver.name,
            idNumber: driver.idNumber,
            phone: driver.phone,
          });
        }
      });
    }
  }

  fs.writeFileSync(statsFile, JSON.stringify(passedDrivers, null, 2));
  fs.writeFileSync(driversPath, "{}");
  res.send("✅ נשמרו סטטיסטיקות ואופסה רשימת הנהגים.");
});

const { exec } = require("child_process");

app.get("/reset-drivers", (req, res) => {
  writeJSON("drivers.json", {});
  exec("pm2 restart driver-system --update-env", (error, stdout, stderr) => {
    if (error) {
      console.error("❌ שגיאה באתחול:", error.message);
      return res.status(500).send("❌ שגיאה באתחול השרת");
    }
    console.log("✅ בוצע Restart לשרת:", stdout);
    res.send("✅ drivers.json אופס בהצלחה והשרת אותחל");
  });
});
// הרצת השרת
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
