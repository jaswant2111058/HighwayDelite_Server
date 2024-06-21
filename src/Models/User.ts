import { Schema, model, Document } from 'mongoose';

// Define TypeScript interfaces for the schema

export interface IUser extends Document {
    first_name: string;
    last_name: string;
    email: string;
    password: string;
    verified: boolean;
    otp: string;
}

const UserSchema: Schema = new Schema({
    first_name: {
        type: String,
        required: true
    },
    last_name: {
        type: String,
        required: false
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    verified: {
        type: Boolean,
        required: true
    },
    otp: {
        type: String,
        required: false
    }
}, {
    timestamps: true
});

// Create the model using the schema and the IUser interface
const User = model<IUser>('User', UserSchema);

export default User;
