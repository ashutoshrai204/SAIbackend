import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";

// Get the __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Define storage settings for multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Specify the directory where files should be stored
    cb(null, path.join(__dirname, "../uploads")); // Correct path to store files in the uploads directory
  },
  filename: function (req, file, cb) {
    // Generate a unique file name using the original name and the current timestamp
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname));
  },
});

// Filter the type of files that can be uploaded (optional)
const fileFilter = (req, file, cb) => {
  const allowedFileTypes = /jpeg|jpg|png|pdf/;
  const extname = allowedFileTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedFileTypes.test(file.mimetype);

  if (mimetype && extname) {
    cb(null, true);
  } else {
    cb(new Error("Only images and PDFs are allowed"));
  }
};

// Initialize the multer upload middleware
export const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB
  fileFilter: fileFilter,
});
