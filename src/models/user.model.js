import mongoose, { mongo } from 'mongoose'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

const userSchema = new mongoose.Schema(
    {
        name:{
            type:String,
            required:true,
            trim:true,
        },
        email:{
            type:String,
            required:true,
            unique:true,
            lowercase:true,
            trim:true,
        },
        password:{
            type:String,
            required:[true,"password is required"]
        },
        address:{
            type:String,
            required:true
        },
        bio:{
            type:String,
            default:''
        },
        profilePic:{
            type:String,
            default:''
        },
        refreshToken:{
            type:String
        },

    },
    {timestamps:true}
)

userSchema.pre("save",async function(next){
    if(!this.isModified("password")){
        return next();
    }
    this.password = await bcrypt.hash(this.password,10)
    next()
})

userSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password,this.password)
}

userSchema.methods.generateAccessToken= function () {
   return jwt.sign(
    {
        _id:this._id,
        email:this.email,
        name:this.name
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
        expiresIn:process.env.ACCESS_TOKEN_EXPIRY
    }
   )
}

userSchema.methods.generateRefreshToken= function () {
    return jwt.sign(
        {
            _id:this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn:process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

 

export const User = mongoose.model("User",userSchema);