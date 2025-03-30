import mongoose from 'mongoose'
import { DB_NAME } from '../constants.js'



const connectDB = async()=>{
    try {
        const res = await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`);
        console.log(`Database Connected successfully !! ${res.connection.host}`);
    } catch (error) {
        console.log(error.message);
        process.exit(1);
    }
}

export default connectDB;