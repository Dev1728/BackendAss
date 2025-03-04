import {asyncHandler} from  '../utils/asyncHandler.js'
import {ApiError} from '../utils/ApiError.js'
import {User} from '../models/user.model.js'
import { ApiResponse } from '../utils/ApiResponse.js'
import cookie from 'cookie-parser'
import crypto from 'crypto'
import nodemailer from 'nodemailer'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import bcrypt from'bcrypt'
dotenv.config()


const generateAccessAndRefreshTokens = async(userId)=>{
    try {
        const user =await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave:false})

        return {accessToken,refreshToken};
    } catch (error) {
        throw new ApiError(500,"Something went Wrong While Generating Access and Refresh Token")
    }
}


const registerUser = asyncHandler(async (req,res) =>{
       
        const {fullName,email,username,password} =req.body
       // console.log("email",email);

        if([fullName,email,username,password].some((field)=>field?.trim() === "")){
            throw new ApiError(400,"All fields are required");
        }
        if(!email.includes('@')){
            throw new ApiError(400,"Email is not correct");
        }

        const existedUser = await User.findOne({
            $or:[{username},{email}]
        })

        if(existedUser){
            throw new ApiError(409,"User with email or username Already exists");
        }
        

       const user =  await User.create({
            fullName,
            email,
            password,
            username:username.toLowerCase()
        })
       const createdUser = await User.findById(user._id).select(
            "-password -refreshToken"
       );

       if(!createdUser){
            throw new ApiError(500,"Something went wrong while registering the user")
       }

       return res.status(201).json( new ApiResponse(200,createdUser,"User registed successfully"))
     
})

const loginUser= asyncHandler(async(req,res)=>{
    

    const {email,username,password} =req.body;
    //console.log(email);

    if(!username && !email ){
        throw new ApiError(400,"username or email is required"); 
    }

    const user =await User.findOne({
        $or:[{username},{email}]
    })
    if(!user){
        throw new ApiError(404,"user does not Exist");
    }
    const isPasswordValid = await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(404,"Invalid user Credentails");
    }

    const {accessToken,refreshToken}=await generateAccessAndRefreshTokens(user._id);

    const loggedInUser = await User.findById(user._id).
    select("-password -refreshToken")

    //console.log(loggedInUser);

    const options = {
        httpOnly:true,
        secure:true
    }

    return res.
    status(200).
    cookie("accessToken",accessToken,options).
    cookie("refreshToken",refreshToken,options).
    json(
        new ApiResponse(
            200,
            {
                user:loggedInUser,accessToken,refreshToken
            },
            "User logged in Successfully"
        )
    )

})


const logOut = asyncHandler(async(req,res)=>{
      await User.findByIdAndUpdate(
        req.user._id,
        {
          $set:{
            refershToken:undefined
          }  
        },
        {
            new:true
        }
      )

    const options = {
        httpOnly:true,
        secure:true
    }
    return res.
    status(200).
    clearCookie("accessToken",options).
    clearCookie("refreshToken",options).
    json(new ApiResponse(200,{},"user logged Out"))

      
})


const refershedAceessToken = asyncHandler(async(req,res)=>{
   try {
     const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
     if(!incomingRefreshToken){
         throw new ApiError(401,"Unauthorised request");
     }
     const decodedToken = jwt.verify(incomingRefreshToken,process.env.REFRESH_TOKEN_SECRET)
     const user = await User.findById(decodedToken?._id)
 
     if(!user){
         throw new ApiError(401,"Invalid refresh token");
     }
 
     if(incomingRefreshTokenc !== user?.refershToken){
         throw new ApiError(401,"Refresh token is expired or used")
     }
 
     const options ={
         httpOnly:true,
         secure:true
     }
     const {accessToken,newRefreshToken} = await generateAccessAndRefreshTokens(user._id);
 
     return res.
     status(200).
     cookie("accessToken",accessToken,options).
     cookie("refreshToken",newRefreshToken,options).
     json(
         new ApiResponse(200,{accessToken,newRefreshToken},"Access token Refreshed Successfully")
     )
   } catch (error) {
        throw new ApiError(401,error?.message || "Invalid Refresh Token");
   }


})  



const forgotPassword = asyncHandler(async (req, res) => {
    try {
        const { email } = req.body;

       
        const user = await User.findOne({ email });
        if (!user) {
            throw new ApiError(404, "User not found or Email is incorrect");
        }

        
        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        //console.log(hashedToken)
      
        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpires = Date.now() + 3600000; 
        await user.save({ validateBeforeSave: false });

        // Send email with reset link
        const resetUrl = `http://localhost:8000/api/v1/users/reset-password/${resetToken}`;

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: { user:"dj64360@gmail.com", pass:"exkj mpvu ffyg tcbj" }
        });

        await transporter.sendMail({
            to: user.email,
            subject: 'Password Reset Request',
            html: `<p>Click <a href="${resetUrl}">here</a> to reset your password. This link is valid for 1 hour.</p>`
        });

        //console.log(resetUrl);

        return res.status(200).json(new ApiResponse(200, "Password reset link sent to email"));

    } catch (error) {
        throw new ApiError(500, error?.message || "Internal server error");
    }
});


const resetPassword = asyncHandler(async (req, res) => {
    try {
        const { token } = req.params;
        const { newPassword } = req.body;

        if (!newPassword || newPassword.trim() === "") {
            throw new ApiError(400, "New password is required");
        }

        
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        // console.log(hashedToken);
        // console.log(token);
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() } // Ensure token is not expired
        });
        //console.log(user)
        if (!user) {
            throw new ApiError(400, "Invalid or expired token");
        }

       
        user.password = await bcrypt.hash(newPassword, 10);

       
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        return res.status(200).json(new ApiResponse(200, "Password has been reset successfully"));

    } catch (error) {
        throw new ApiError(500, error?.message || "Internal Server Error");
    }
});



export {
    registerUser,
    loginUser,
    logOut,
    refershedAceessToken,
    forgotPassword,
    resetPassword
};