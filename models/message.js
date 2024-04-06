const mongoose = require('mongoose')

const MessageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'user' },
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'user' },
    text: String,
}, { timestamps: true });

module.exports = mongoose.model("Message", MessageSchema);