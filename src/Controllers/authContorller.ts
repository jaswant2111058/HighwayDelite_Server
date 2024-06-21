import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcrypt';
import jwt, { TokenExpiredError } from 'jsonwebtoken';
import User, { IUser } from '../Models/User';
import sendMail from '../Utils/mailLinkSender';
import { generateOTP } from '../Utils/otpGenrater';


// -------------- authControllers --------------

const hashPassword = async (password: string): Promise<string> => {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
};

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
            res.status(403).send({ message: "email already exists" });
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
        const password: any = jwt.verify(token, process.env.JWT_SECRET as string) as { password: string };
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


export const verifyOtp = async (req: Request, res: Response) => {
    const { otp, email } = req.body;
    try {
        const user: any = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                message: "User email does not exist"
            });

        }

        if (user.verified) {
            return res.status(403).json({
                message: "User account already verified"
            });

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
        return res.status(200).json({
            message: "account Verified successfuly"
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
};

export const reSendOtp = async (req: Request, res: Response) => {

    try {
        const { email } = req.body;
        console.log(email)
        const user: any = await User.findOne({ email });
        if (!user) {
            return res.status(401).send({ message: "email not exists in Data Base" });
        }
        const now = new Date();
        const fifteenMinutesAgo = new Date(now.getTime() - 15 * 60 * 1000);

        if (user?.updatedAt > fifteenMinutesAgo) {
            res.status(403).json({
                message: "Last OTP is still valid try after 15 min"
            });
            return;
        }
        const otp = generateOTP()
        await User.updateOne({ email }, { otp })
        sendMail({ email, token: "not vaild option", otp });
        res.status(200).send({ message: `mail has been sent to the email Id ${email}` });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
};



