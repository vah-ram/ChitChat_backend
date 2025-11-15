import mongoose from "mongoose";

const MessageSchema = new mongoose.Schema({
    from: {
        type: mongoose.Schema.Types.ObjectId,
        required: true
    },
    to: {
        type: mongoose.Schema.Types.ObjectId,
        required: true
    },
    message: {
        type: String,
        required: true
    }
}, {
    timestamps: true
});

export const Message = mongoose.model("Message", MessageSchema);
