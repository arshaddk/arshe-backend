// ─────────────────────────────────────────────────────────────────
//  Arshé Backend — Express + Razorpay + MongoDB Auth
//  Endpoints:
//    POST  /api/create-order           — Razorpay order creation
//    POST  /api/verify-payment         — Razorpay signature verification
//    POST  /api/auth/signup            — Register new user
//    POST  /api/auth/login             — Login existing user
//    PATCH /api/auth/update-profile    — Update name / email  [auth required]
//    POST  /api/auth/change-password   — Change password       [auth required]
//
//  Environment variables required (set in Railway dashboard):
//    RAZORPAY_KEY_ID
//    RAZORPAY_KEY_SECRET
//    MONGODB_URI       ← from MongoDB Atlas (see README)
//    JWT_SECRET        ← any long random string e.g. "arshe_super_secret_2025"
// ─────────────────────────────────────────────────────────────────

import express from "express"
import Razorpay from "razorpay"
import crypto from "crypto"
import cors from "cors"
import "dotenv/config"
import { MongoClient, ObjectId } from "mongodb"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"

const app = express()
app.use(cors())
app.use(express.json())

// ── MONGODB CONNECTION ────────────────────────────────────────────
let db
const connectDB = async () => {
    if (db) return db
    const client = new MongoClient(process.env.MONGODB_URI)
    await client.connect()
    db = client.db("arshe")
    console.log("MongoDB connected")
    return db
}

// ── RAZORPAY ──────────────────────────────────────────────────────
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
})

// POST /api/create-order
app.post("/api/create-order", async (req, res) => {
    const { amount, currency = "INR", receipt } = req.body
    if (!amount || amount < 100)
        return res.status(400).json({ error: "Amount must be >= 100 paise" })
    try {
        const order = await razorpay.orders.create({ amount, currency, receipt })
        res.json({ order_id: order.id, amount: order.amount, currency: order.currency })
    } catch (err) {
        console.error("Create order error:", err)
        res.status(500).json({ error: "Order creation failed" })
    }
})

// POST /api/verify-payment
app.post("/api/verify-payment", (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature)
        return res.status(400).json({ error: "Missing fields" })

    const expected = crypto
        .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
        .update(`${razorpay_order_id}|${razorpay_payment_id}`)
        .digest("hex")

    if (expected !== razorpay_signature)
        return res.status(400).json({ error: "Signature mismatch" })

    res.json({ success: true })
})

// ── AUTH ──────────────────────────────────────────────────────────

// POST /api/auth/signup
app.post("/api/auth/signup", async (req, res) => {
    const { name, email, password } = req.body

    if (!email || !password || !name)
        return res.status(400).json({ error: "Name, email and password are required" })
    if (password.length < 6)
        return res.status(400).json({ error: "Password must be at least 6 characters" })

    try {
        const database = await connectDB()
        const users = database.collection("users")

        // Check if email already exists
        const existing = await users.findOne({ email: email.toLowerCase() })
        if (existing)
            return res.status(400).json({ error: "An account with this email already exists" })

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12)

        // Save user
        const result = await users.insertOne({
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            createdAt: new Date(),
        })

        // Issue JWT
        const token = jwt.sign(
            { userId: result.insertedId, email: email.toLowerCase() },
            process.env.JWT_SECRET,
            { expiresIn: "30d" }
        )

        res.status(201).json({ name, email: email.toLowerCase(), token })
    } catch (err) {
        console.error("Signup error:", err)
        res.status(500).json({ error: "Something went wrong. Please try again." })
    }
})

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body

    if (!email || !password)
        return res.status(400).json({ error: "Email and password are required" })

    try {
        const database = await connectDB()
        const users = database.collection("users")

        // Find user
        const user = await users.findOne({ email: email.toLowerCase() })
        if (!user)
            return res.status(401).json({ error: "No account found with this email" })

        // Check password
        const valid = await bcrypt.compare(password, user.password)
        if (!valid)
            return res.status(401).json({ error: "Incorrect password" })

        // Issue JWT
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "30d" }
        )

        res.json({ name: user.name, email: user.email, token })
    } catch (err) {
        console.error("Login error:", err)
        res.status(500).json({ error: "Something went wrong. Please try again." })
    }
})

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────
// Verifies the Bearer token and attaches decoded payload to req.user
const requireAuth = (req, res, next) => {
    const header = req.headers.authorization || ""
    const token = header.startsWith("Bearer ") ? header.slice(7) : null
    if (!token)
        return res.status(401).json({ error: "Authentication required" })
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET)
        next()
    } catch {
        return res.status(401).json({ error: "Invalid or expired token" })
    }
}

// PATCH /api/auth/update-profile
// Body: { name, email }
app.patch("/api/auth/update-profile", requireAuth, async (req, res) => {
    const { name, email } = req.body

    if (!name || !name.trim())
        return res.status(400).json({ error: "Name cannot be empty" })
    if (!email || !email.includes("@"))
        return res.status(400).json({ error: "Invalid email address" })

    try {
        const database = await connectDB()
        const users = database.collection("users")

        // If email is changing, make sure it isn't taken by another account
        const newEmail = email.trim().toLowerCase()
        if (newEmail !== req.user.email) {
            const conflict = await users.findOne({ email: newEmail })
            if (conflict)
                return res.status(400).json({ error: "That email is already in use" })
        }

        await users.updateOne(
            { _id: new ObjectId(req.user.userId) },
            { $set: { name: name.trim(), email: newEmail, updatedAt: new Date() } }
        )

        res.json({ name: name.trim(), email: newEmail })
    } catch (err) {
        console.error("Update profile error:", err)
        res.status(500).json({ error: "Something went wrong. Please try again." })
    }
})

// POST /api/auth/change-password
// Body: { currentPassword, newPassword }
app.post("/api/auth/change-password", requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body

    if (!currentPassword || !newPassword)
        return res.status(400).json({ error: "Both current and new password are required" })
    if (newPassword.length < 6)
        return res.status(400).json({ error: "New password must be at least 6 characters" })

    try {
        const database = await connectDB()
        const users = database.collection("users")

        const user = await users.findOne({ _id: new ObjectId(req.user.userId) })
        if (!user)
            return res.status(404).json({ error: "User not found" })

        const valid = await bcrypt.compare(currentPassword, user.password)
        if (!valid)
            return res.status(401).json({ error: "Current password is incorrect" })

        const hashed = await bcrypt.hash(newPassword, 12)
        await users.updateOne(
            { _id: new ObjectId(req.user.userId) },
            { $set: { password: hashed, passwordChangedAt: new Date() } }
        )

        res.json({ success: true })
    } catch (err) {
        console.error("Change password error:", err)
        res.status(500).json({ error: "Something went wrong. Please try again." })
    }
})

// ── START ─────────────────────────────────────────────────────────
app.listen(process.env.PORT || 3001, "0.0.0.0", () =>
    console.log("Arshé server running on port", process.env.PORT || 3001)
)