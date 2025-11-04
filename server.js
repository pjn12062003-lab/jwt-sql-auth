import express from "express";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import db from "./db.js";
import multer from "multer";
import path from "path";

dotenv.config();
const app = express();
app.use(express.json());
app.use("/uploads", express.static("uploads")); // make images accessible

const JWT_SECRET = process.env.JWT_SECRET;

/* -------------------------------
   User Registration
--------------------------------*/
app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Username and password required" });

  const [user] = await db
    .promise()
    .query("SELECT * FROM users WHERE username = ?", [username]);
  if (user.length > 0)
    return res.status(400).json({ message: "Username already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);
  await db
    .promise()
    .query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [
      username,
      hashedPassword,
      role || "user",
    ]);

  res.json({ message: "User registered successfully" });
});

/* -------------------------------
   Login User
--------------------------------*/
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await db
    .promise()
    .query("SELECT * FROM users WHERE username = ?", [username]);
  if (rows.length === 0)
    return res.status(401).json({ message: "Invalid credentials" });

  const user = rows[0];
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "24h" }
  );

  res.json({ message: "Login successful", token, role: user.role });
});

/* -------------------------------
   Token Authentication Middleware
--------------------------------*/
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err)
      return res.status(403).json({ message: "Invalid or expired token" });
    req.user = user;
    next();
  });
}

/* -------------------------------
   Role-based Authorization
--------------------------------*/
function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role)
      return res
        .status(403)
        .json({ message: "Access denied: insufficient permissions" });
    next();
  };
}

/* -------------------------------
   Protected Routes
--------------------------------*/
app.get("/admin/dashboard", authenticateToken, authorizeRole("admin"), (req, res) => {
  res.json({ message: `Welcome Admin ${req.user.username}` });
});

app.get("/user/dashboard", authenticateToken, authorizeRole("user"), (req, res) => {
  res.json({ message: `Welcome User ${req.user.username}` });
});

/* -------------------------------
   Multer Configuration
--------------------------------*/
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname),
});

const fileFilter = (req, file, cb) => {
  const allowed = /jpeg|jpg|png|gif/;
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowed.test(ext)) cb(null, true);
  else cb(new Error("Only image files allowed!"));
};

const upload = multer({ storage, fileFilter });

/* -------------------------------
   Add Image API
--------------------------------*/
app.post("/image/add", authenticateToken, upload.single("image"), async (req, res) => {
  const { title } = req.body;
  if (!req.file)
    return res.status(400).json({ message: "Image is required" });

  await db
    .promise()
    .query("INSERT INTO images (user_id, title, image_path) VALUES (?, ?, ?)", [
      req.user.id,
      title,
      req.file.path,
    ]);

  res.json({ message: "Image uploaded successfully", path: req.file.path });
});

/* -------------------------------
   Edit Image API
--------------------------------*/
app.put("/image/edit/:id", authenticateToken, upload.single("image"), async (req, res) => {
  const { title } = req.body;
  const imageId = req.params.id;
  const imagePath = req.file ? req.file.path : null;

  if (!title && !imagePath)
    return res
      .status(400)
      .json({ message: "Provide a title or a new image" });

  const fields = [];
  const values = [];

  if (title) {
    fields.push("title = ?");
    values.push(title);
  }
  if (imagePath) {
    fields.push("image_path = ?");
    values.push(imagePath);
  }

  values.push(imageId);

  await db
    .promise()
    .query(`UPDATE images SET ${fields.join(", ")} WHERE id = ?`, values);

  res.json({ message: "Image updated successfully" });
});

/* -------------------------------
   Start Server
--------------------------------*/
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
