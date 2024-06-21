import { Request, Response, NextFunction } from 'express';
import jwt, { TokenExpiredError } from 'jsonwebtoken';
import User from '../Models/User';






export const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const authorizationHeaderToken = req.headers.authorization;
        if (!authorizationHeaderToken) {
            return res.status(401).json({
                message: "Unauthorized"
            });
        }

        const token = authorizationHeaderToken;
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { email: string };

        const user = await User.findOne({ email: decoded.email }).select("-password");
        if (!user) {
            return res.status(401).json({
                message: "Unauthorized"
            });
        }

        (req as any).email = decoded.email;
        next();
    } catch (error) {
        if (error instanceof TokenExpiredError) {
            return res.status(401).json({
                message: "Token expired"
            });
        }

        console.error(typeof error, error);
        res.status(500).json({
            message: "Something went wrong"
        });
    }
};
