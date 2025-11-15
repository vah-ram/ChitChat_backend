import express from "express";
import bcrypt from "bcrypt";
import { User } from "../models/UserModel.js";

const router = express.Router();

router.post("/register", async( req, res ) => {
    const { username, email, password } = req.body;

    try {

        const hasUsername = await User.findOne({ username });
            if(hasUsername) {
                return res.json({ 
                        status: false, 
                        msg: "Username is already exists!"});
            };

        const hasEmail = await User.findOne({ email });
            if(hasEmail) {
                return res.json({ 
                        status: false, 
                        msg: "Email is already exists!"});
            };

        const user = await User.create({
            username: username,
            email: email,
            password: await bcrypt.hash(password, 10)
        });

        await user.save();

        return res.json({ status: true, user });

    } catch(err) {
        console.error(err)
    }
});

router.post("/login", async( req, res  ) => {
    const { email, password } = req.body;

    try {

        const user = await User.findOne({ email });
            if(!user) {
                return res.json({ 
                    status: false, 
                    msg: "User with this e-mail not found!"
                });
            };
        
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if(isPasswordValid) {

            return res.json({ 
                status: true,
                user
            });

        } else {
            return res.json({ 
                status: false, 
                msg: "Password is incorrect!!!"
            });
        }
        
    } catch(err) {
        console.error(err);
    }
});

router.get('/search-user', async( req, res ) => {
    const value = req.query.value;

    try {
        const users = await User.find({
            username: { $regex: `^${value}`, $options: "i" }
        });

        if(users.length > 0) {
            return res.json({ status: true, users });
        } else {
            return res.json({ status: false });
        };

    } catch(err) {
        console.error(err);
    };

});


export default router;