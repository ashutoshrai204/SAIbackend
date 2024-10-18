import jwt from "jsonwebtoken";
import { User } from "../models/User.js";

export const isAuth = async (req, res, next) => {
  try {
    const token = req.headers.token;

    if (!token) {
      return res.status(403).json({
        message: "Please Login",
      });
    }

    const decodedData = jwt.verify(token, process.env.Jwt_Sec);
    
    // Find the user by ID
    req.user = await User.findById(decodedData._id);

    // Check if the user exists
    if (!req.user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Set adminId if the user is an admin
    if (req.user.role === "admin") {
      req.adminId = req.user._id; // Set adminId for approval entries
    } else {
      req.adminId = null; // or handle the case if necessary
    }

    next();
  } catch (error) {
    res.status(500).json({
      message: "Login first",
    });
  }
};

export const isAdmin = (req, res, next) => {
  if (!req.adminId) {
    return res.status(403).json({
      message: "You are not an admin",
    });
  }

  next();
};
