import mongoose from "mongoose";

const schema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true, // creates an index to enforce unique values
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      default: "user", // default role is "user"
      enum: ["user", "admin"], // only allow "user" or "admin"
      lowercase: true, // always store in lowercase
    },
  },
  {
    timestamps: true, // this will add createdAt and updatedAt fields
  }
);

export const User = mongoose.model("User", schema);
