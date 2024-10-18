import express from "express";
import { getAllRequests, viewUserRequest, updateRequestStatus } from "../controllers/admin.js";
import { isAdmin, isAuth } from "../middleware/isAuth.js"; // Assuming admin auth middleware

const router = express.Router();

router.get("/requests", isAuth, isAdmin, getAllRequests);
router.get("/requests/:id", isAuth, isAdmin, viewUserRequest);
router.put("/requests/:id/status", isAuth, isAdmin, updateRequestStatus);

export default router;
