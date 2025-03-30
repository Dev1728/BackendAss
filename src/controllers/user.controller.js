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


const createProfile = async (req, res) => {
    try {
        const { name, email, address, password } = req.body;
        console.log("Request Body:", req.body); 

        if ([name, email, address, password].some((field) => field?.trim() === "")) {
            throw new ApiError(400, "All fields are required");
        }
        if (!email.includes('@')) {
            throw new ApiError(400, "Email is not correct");
        }

        const existedUser = await User.findOne({ email });
        console.log("Existed User:", existedUser); 

        if (existedUser) {
            throw new ApiError(409, "User with email or username Already exists");
        }

        const user = await User.create({
            name,
            email,
            password,
            address,
        });
        console.log("Created User:", user); 

        const token = user.generateAccessToken();
        console.log("Generated Token:", token); 


        const createdUser = await User.findById(user._id).select("-password ");
        console.log("Created User (No Password):", createdUser); 

        if (!createdUser) {
            throw new ApiError(500, "Something went wrong while registering the user");
        }

        return res.status(201).json(new ApiResponse(200, createdUser, "User registed successfully"));
    } catch (error) {
        console.error("Error in createProfile:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

const loginUser= asyncHandler(async(req,res)=>{
    

    const {email,password} =req.body;
    //console.log(email);

    if(!password || !email ){
        throw new ApiError(400,"password or email is required"); 
    }

    const user =await User.findOne({email})
    
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



const viewUserProfile = async(req,res)=>{
    try {
        const {profileId} = req.params;
    
        if(!profileId){
            return res.status(404).json({success:false,message:"profile ID is required"});
        }
    
        const userProfile = await User.findById(profileId);
        if(!userProfile){
            return res.status(404).json({success:false,message:"profile not found "});
        }
    
        return res.status(200).json({success:true,data:userProfile ,message:"user profile successfully retreive"});
    } catch (error) {
        console.log(error.message);
        return res.status(500).json({success:false,message:"Internal serve error"});
    }
}

const updateProfile = async(req,res)=>{
    try {
        const {profileId} = req.params;
        

        if(!profileId){
            return res.status(401).json({success:false,message:"profile ID not found "});
        }

        
        const updateData = req.body;
  
        if(!Object.keys(updateData).length=== 0 ){
            return res.status(400).json({success:false,message:"At least one field is required"});
        }

        const updateUser =await User.findByIdAndUpdate(
            profileId,
            {$set:updateData},
            {new:true,runValidators:true}
        ).select("-password")

        if(!updateUser){
            return res.status(404).json({success:false,message:"UserProfile not Found"});
        }

        return res.status(200).json({success:true,data:updateUser,message:"UserProfile updated Successfully."})
     
    } catch (error) {
   
        console.error(error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      
    }
}



export {
    createProfile,
    loginUser,
    logOut,
    refershedAceessToken,
    updateProfile,
    viewUserProfile
};