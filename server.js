// server.js
import express from "express"
import Razorpay from "razorpay"
import crypto from "crypto"
import cors from "cors"
import "dotenv/config"

const app = express()
app.use(cors())
app.use(express.json())

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

app.listen(process.env.PORT || 3001, () =>
    console.log("Server running")
)
