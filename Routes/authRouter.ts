import express, { Request, Response } from 'express';
import { body } from 'express-validator';
import * as authControllers from '../controllers/authContorller';

const router = express.Router();

router.post('/signup',
    [
        body('email').exists().withMessage('email is required'),
        body('password').exists().withMessage('Password is required'),
        body('first_name').exists().withMessage('first_name is required'),
        body('last_name').exists().withMessage('last_name is required'),
    ],
    authControllers.signup
);



router.post('/login',
    [
        body('email').exists().withMessage('email is required'),
        body('password').exists().withMessage('Password is required'),
    ],
    authControllers.login
);


router.post('/otp/verification',
    [
        body('email').exists().withMessage('email is required'),
        body('otp').exists().withMessage('otp is required'),
    ],
    authControllers.verifyOtp
);

router.get('/email/verification',
    authControllers.verifySave
);



export default router;
