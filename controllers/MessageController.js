import express from "express";
import { Message } from "../models/MessageModel.js";

const router = express.Router();

router.post('/add-message', async( req, res ) => {
    const { from, to, message } = req.body;

    const msg = await Message.create({
        from: from,
        to: to,
        message: message
    });

    if(msg) {
        return res.json({ status: true })
    };

});

router.get('/get-message', async( req, res ) => {

    const { myId, contactId } = req.query;

    const messages = await Message.find({
        $or: [
            { from: myId, to: contactId },
            { from: contactId, to: myId }
        ]
    });

    if(messages) {
        return res.json({ status: true, messages})
    } else {
        return res.json({ status: false })
    }

});

export default router;