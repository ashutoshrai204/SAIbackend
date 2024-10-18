import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import { ConnectDB } from "./database/db.js";
import cors from "cors";

dotenv.config();

const app = express();

// Manually define __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

//using middlewares
app.use(express.json());
app.use(cors());

const port = process.env.PORT;

app.get("/", (req, res) => {
  res.send("Server is working");
});

// Serve static files from the "uploads" directory
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

//importing routes

import userRoutes from "./routes/user.js";
import adminRoutes from "./routes/admin.js";

//Using routes
app.use("/api", userRoutes);
app.use("/api", adminRoutes);

app.listen(port, () => {
  console.log(`Server is running on port http://localhost:${port}`);
  ConnectDB();
});
