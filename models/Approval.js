import mongoose from "mongoose";

const schema = new mongoose.Schema(
  {
    requestId: {
      type: mongoose.Schema.Types.ObjectId, // references the Request model
      ref: "Request", // name of the Request model
      required: true,
    },
    adminId: {
      type: mongoose.Schema.Types.ObjectId, // references the Admin model
      ref: "admin", // name of the Admin model
      required: true,
    },
    status: {
      type: String,
      required: true,
      enum: ["approved", "rejected"], // only allow "approved" or "rejected"
      lowercase: true, // store in lowercase
    },
    comments: {
      type: String, // optional feedback field
      default: "", // default empty string if no feedback is provided
    },
  },
  {
    timestamps: true, // adds createdAt and updatedAt fields
  }
);

export const Approval = mongoose.model("Approval", schema);
