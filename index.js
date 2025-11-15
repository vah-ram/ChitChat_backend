import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import http from "http";
import { Server } from "socket.io";
import UserRouter from "./controllers/UserController.js"
import MessageRouter from "./controllers/MessageController.js"

const app = express();

dotenv.config();

app.use(cors());
app.use(express.json());
app.use("/api/", UserRouter);
app.use("/message/", MessageRouter);

const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: process.env.CLIENT_HOST
    }
});

mongoose.connect(process.env.MONGODB_LINK)
        .then(() => console.log("Mongodb connected successfully!!!"))
        .catch((err) => console.error(err));

server.listen(5000, () => {
    console.log("Server is listening!!!")
});

io.on("connection", (socket) => {
    console.log(`Socket connected to Id: ${socket.id}`);

    socket.on("send_message", () => {
        io.emit("receive_message");
    });
});