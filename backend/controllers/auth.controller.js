import express from "express";
import { redis } from "../config/redis.js";
import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

// Generate access and refresh tokens
const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });
  return { accessToken, refreshToken };
};

// Store refresh token in Redis with expiration
const storeRefreshToken = async (userId, refreshToken) => {
  // Try the object option first (recommended for redis v4+)
  await redis.set(
    `refresh_token:${userId}`,
    refreshToken,
    {
      EX: 7 * 24 * 60 * 60,
    }
  );
};


// Set HttpOnly cookies for tokens
const setCookies = (res, accessToken, refreshToken) => {
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000, // 15 minutes
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
};

export const signup = async (req, res) => {
  const { name, email, password } = req.body;

  // Basic validation (optional, add more if you want)
  if (!name || !email || !password) {
    return res.status(400).json({ message: "Name, email, and password are required." });
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const user = await User.create({ name, email, password });

    const { accessToken, refreshToken } = generateTokens(user._id);
    await storeRefreshToken(user._id.toString(), refreshToken);
    setCookies(res, accessToken, refreshToken);

    res.status(201).json({
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      message: "User created successfully",
    });
  } catch (error) {
    console.error("Error in signup controller:", error);
    res.status(500).json({ message: error.message || "Server error" });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    const user = await User.findOne({ email });
    if (user && (await user.comparePassword(password))) {
      const { accessToken, refreshToken } = generateTokens(user._id);
      await storeRefreshToken(user._id.toString(), refreshToken);
      setCookies(res, accessToken, refreshToken);

      return res.json({
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      });
    } else {
      return res.status(401).json({ message: "Invalid email or password" });
    }
  } catch (error) {
    console.error("Error in login controller:", error);
    res.status(500).json({ message: error.message || "Server error" });
  }
};

export const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken;
    if (refreshToken) {
      const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      await redis.del(`refresh_token:${decoded.userId}`);
      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");
      return res.status(200).json({ message: "Logged out successfully" });
    } else {
      return res.status(400).json({ message: "No refresh token found" });
    }
  } catch (error) {
    console.error("Error in logout controller:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

export const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken)
      return res.status(401).json({ message: "No refresh token provided" });

    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const storedToken = await redis.get(`refresh_token:${decoded.userId}`);

    if (storedToken !== refreshToken)
      return res.status(403).json({ message: "Invalid refresh token" });

    const accessToken = jwt.sign(
      { userId: decoded.userId },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    });
    res.json({ message: "Token refreshed successfully" });
  } catch (error) {
    console.error("Error in refreshToken controller:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

export const getProfile = async (req, res) => {
  try {
    // Assuming req.user is set by some authentication middleware
    res.json(req.user);
  } catch (error) {
    console.error("Error in getProfile controller:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};
