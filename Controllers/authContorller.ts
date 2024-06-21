import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcrypt';
import jwt, { TokenExpiredError } from 'jsonwebtoken';
import User, { IUser } from '../Models/User';
import sendMail from '../utils/mailLinkSender';
import { generateOTP } from '../Utils/otpGenrater';


// -------------- authControllers --------------

export const login = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                message: "user email does not exist"
            });
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(401).json({
                message: "Incorrect password"
            });
        }

        const token = jwt.sign({ email: email }, process.env.JWT_SECRET as string, {
            expiresIn: "1d"
        });

        res.status(200).send({
            user_id: user._id,
            email: email,
            first_name: user.first_name,
            last_name: user.last_name,
            token: token,
            expires_in: new Date(Date.now() + 60 * 60 * 1000),
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
};

export const signup = async (req: Request, res: Response) => {
    try {
        const { first_name, last_name, email, password } = req.body;
        const preEmail = await User.findOne({ email });
        if (preEmail) {
            res.send({ message: "email already exists" });
        } else {
            const token = jwt.sign({ password: password }, process.env.JWT_SECRET as string, {
                expiresIn: `${1000 * 60 * 5}`
            });
            const otp = generateOTP()
            const hash = await hashPassword(password)
            const detail: Partial<IUser> = {
                email,
                password: hash,
                first_name,
                last_name,
                otp,
                verified: false
            };
            const newUser = new User(detail);
            const savedUser = await newUser.save();
            sendMail({ email, token, otp });
            res.status(200).send({ message: `mail has been sent to the email Id ${email}` });
        }
    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
};

export const verifySave = async (req: Request, res: Response) => {
    try {
        const token = req.query.token as string;
        const email = req.query.email as string;
        const password = jwt.verify(token, process.env.JWT_SECRET as string) as { password: string };
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                message: "user email does not exist"
            });
        }
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(401).json({
                message: "Invalid Token"
            });
        }
        else {
            await User.updateOne({ email }, { verified: true })
            res.status(200).json({
                message: "account verified"
            })
        }
    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
};


export const verifyOtp = async (req: Request, res: Response): Promise<void> => {
    const { otp, email } = req.body;

    try {
        const user: any = await User.findOne({ email });
        if (!user) {
            res.status(401).json({
                message: "User email does not exist"
            });
            return;
        }

        if (user.verified) {
            res.status(402).json({
                message: "User account already verified"
            });
            return;
        }

        const now = new Date();
        const fifteenMinutesAgo = new Date(now.getTime() - 15 * 60 * 1000);

        if (user?.updatedAt < fifteenMinutesAgo) {
            res.status(403).json({
                message: "OTP expired"
            });
            return;
        }

        if (user.otp !== otp) {
            res.status(401).json({
                message: "Invalid OTP"
            });
            return;
        }

        await User.updateOne(
            { email },
            { $set: { verified: true } }
        );

    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
};

