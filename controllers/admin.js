import { Request } from "../models/Request.js";
import { Approval } from "../models/Approval.js";
import TryCatch from "../middleware/TryCatch.js"; // Import the TryCatch middleware

// Get all user requests for approval
export const getAllRequests = TryCatch(async (req, res) => {
  const requests = await Request.find().populate("userId", "name email");
  res.status(200).json(requests);
});

// View a specific user's request
export const viewUserRequest = TryCatch(async (req, res) => {
  const { id } = req.params; // Request ID

  const request = await Request.findById(id).populate("userId", "name email");

  if (!request) {
    return res.status(404).json({ message: "Request not found" });
  }

  res.status(200).json({
    request,
    fileDownloadUrl: `${req.protocol}://${req.get("host")}${request.fileUrl}`, // Full URL for downloading the file
  });
});


// Approve or reject the user's request
export const updateRequestStatus = TryCatch(async (req, res) => {
  const { id } = req.params; // Request ID passed in the URL
  const { status, comments } = req.body; // Status and optional comments sent in the body
  const adminId = req.adminId; // Assume adminId is set in middleware/auth

  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ message: "Invalid status" });
  }

  const request = await Request.findById(id);
  if (!request) {
    return res.status(404).json({ message: "Request not found" });
  }

  // Update the request's status
  request.status = status;
  await request.save();

  // Create an approval entry
  const approval = new Approval({
    requestId: id,
    adminId,
    status,
    comments: comments || "", // Optional feedback
  });
  await approval.save();

  res.status(200).json({ message: `Request ${status}`, approval });
});
