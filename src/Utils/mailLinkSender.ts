import nodemailer from 'nodemailer';

interface SendMailOptions {
    email: string;
    token: string;
    otp: string;
}

const sendMail = ({ email, token, otp }: SendMailOptions): void => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'jkstar0123@gmail.com',
            pass: process.env.EMAIL_PASS,
        }
    });

    const mailOptions = {
        from: 'jkstar0123@gmail.com',
        to: email,
        subject: 'Register Email Verification',
        html: `<html><a href="${process.env.ORIGIN}/email/verification?token=${token}&email=${email}">Verify</a> 

<h1>Your one-time OTP is ${otp}</h1>
</html>`
    };

    console.log(mailOptions);

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
};

export default sendMail;
