import express from "express";
import {
  createRequest,
  getMyRequests,
  loginUser,
  myProfile,
  register,
  verifyUser,
} from "../controllers/user.js";
import { isAuth } from "../middleware/isAuth.js";
import { upload } from "../middleware/fileUpload.js";

const router = express.Router();
router.post("/user/register", register);
router.post("/user/verify", verifyUser);
router.post("/user/login", loginUser);
router.get("/user/me", isAuth, myProfile);
router.post("/requests", upload.single("file"), isAuth, createRequest); // Single route for creating requests with file upload
router.get("/user/requests", isAuth, getMyRequests); 

export default router;
