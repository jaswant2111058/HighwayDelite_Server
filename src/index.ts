import dotenv from 'dotenv';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import logger from 'morgan';
import mongoose from 'mongoose';
import cors from 'cors';
import os from 'os';

// Load environment variables
dotenv.config();

// Import routes


// import indexRouter from './routes/index';
// import authRouter from './routes/user';


// Initialize Express app
const app = express();

// Configure mongoose
mongoose.set('strictQuery', true);
mongoose.connect(process.env.DB_URI as string)
.then(() => console.log("Connected to MongoDB"))
.catch(err => console.log(err));

// Middleware setup
app.use(cors({
  origin: "*",
  exposedHeaders: 'Authorization'
}));
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Route setup
// app.use('/', indexRouter);
// app.use('/', authRouter);


// Function to get local IPv4 address
const getLocalIPv4Address = (): string | undefined => {
  const ifaces = os.networkInterfaces();
  for (const iface in ifaces) {
    for (const details of ifaces[iface]!) {
      if (details.family === 'IPv4' && !details.internal) {
        return details.address;
      }
    }
  }
};

// Start the server
const port = process.env.PORT || '5000';
const server = app.listen(port, () => {
  console.log("Server is up");
  const host = getLocalIPv4Address();
  console.log(`Server is running at http://${host}:${(server.address() as import('net').AddressInfo).port}`);
});
