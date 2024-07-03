import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import jwt from "jsonwebtoken"
import mongoose, { Mongoose } from "mongoose";
import { ApiResponse } from "../utils/ApiResponse.js";
import { validate } from "npm/lib/config/core.js";


const generateAccessAndRefereshTokens = async(userId) => {
    
  try {
    const user = await User.findById(userId)
    const accessToken = user.generateAccessToken()
    const refreshToken = user.generateRefreshToken()
  
    user.refreshToken = refreshToken
    await user.save({
      validateBeforeSave: false
    })
  
    return {accessToken, refreshToken}
  } 
  catch (error) {
    throw new ApiError(500, "Something went wrong whiel generating access and refresh Token")  
  }

}

const registerUser = asyncHandler( async(req, res) => {
  const {fullName, email, username, password} = req.body

  if(fullName?.trim() == "") {
    throw new ApiError(400, "All fields are required")
  }
  if(email?.trim() == "") {
    throw new ApiError(400, "All fields are required")
  }
  if(username?.trim() == "") {
    throw new ApiError(400, "All fields are required")
  }
  if(password?.trim() == "") {
    throw new ApiError(400, "All fields are required")
  }

  const existedUser = await User.findOne({
    $or: [{username}, {email}]
  })  


  if(existedUser) {
    throw new ApiError(400, "User with that username or email already exists")
  }

  const avatarLocalPath = req.files?.avatar[0]?.path;
  //const coverImageLocalPath = req.files?.coverImage[0]?.path;

  let coverImageLocalPath;
  if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
      coverImageLocalPath = req.files.coverImage[0].path
  }

  if(!avatarLocalPath) {
    throw new ApiError(400, "Avatar is required ")
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath)
  const coverImage = await uploadOnCloudinary(coverImageLocalPath)

  if(!avatar) {
    throw new ApiError(400,  "Avatar file is required")
  }

  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email, 
    password,
    username: username.toLowerCase()
})

  const createdUser = await User.findById(user._id).select(
  "-password -refreshToken"
)

  if (!createdUser) {
  throw new ApiError(500, "Something went wrong while registering the user")
}

  return res
  .status(201)
  .json( new ApiResponse(200, createdUser, "User registered succesfully")
  )


})

const loginUser = asyncHandler( async(req, res) => {
  const {email, username, password} = req.body

  if(!username && !email) {
    throw new ApiError(400, "Username or email is required")
  }

  const user = await User.findOne({
    $or: [{username}, {email}]
  })

  if(!user) {
    throw new ApiError(404, "User does not exist")
  }

  const isPasswordValid = await user.isPasswordCorrect(password)
  
  if(!isPasswordValid) {
    throw new ApiError(401, "Invalid User Credentials")
  }

  const {accessToken, refreshToken} = await generateAccessAndRefereshTokens(user._id)

  const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

  const options = {
    httpOnly: true,
    secure: true
  }

  return res
  .status(200)
  .cookie("accessToken", accessToken, options)
  .cookie("refreshToken", refreshToken, options)
  .json(
    new ApiResponse(
      200,
      {
        user: loggedInUser ,accessToken, refreshToken
      },

      "User logged in successfully"
    )
  )
})

const logoutUser = asyncHandler(async(req, res) => {
  await User.findOneAndUpdate(
    req.user._id,

    {
      $unset: {
        refreshToken: 1,
      }
    },

    {
      new: true
    }
  )

  const options = {
    httpOnly: true,
    secure: true
  }


  return res
  .status(200)
  .clearCookie("accessToken", options)
  .clearCookie("refreshToken", options)
  .json( new ApiResponse(200, {}, "User logged Out Succesfully"))
  
})

const refreshAccessToken = asyncHandler(async (req, res) => {

  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

  if(!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized Request ")
  }

 try {
   const decodedToken = jwt.verify(
     incomingRefreshToken, 
     process.env.REFRESH_TOKEN_SECRET)
 
     const user = await User.findById(decodedToken?._id)
 
     if(!user){
       throw new ApiError(401, "Invalid Refresh Token")
     }
 
     if(incomingRefreshToken !== user?.refreshToken){
       throw new ApiError(401, "Refresh token must have expired")
     }
 
     const options = {
       httpOnly: true,
       secure: true
     }
 
     const { accessToken, newRefreshToken } = await generateAccessAndRefereshTokens(user._id) 
 
     return res
     .status(200)
     .cookie("accessToken", accessToken, options)
     .cookie("refreshToken", newRefreshToken, options)
     .json(
      new ApiResponse( 200,
        {accessToken, refreshToken: newRefreshToken},
        "Access Token refreshed")
     )
 } 
 catch (error) {
    throw new ApiError(401, error?.message || "Invalid Refresh Token")
 }

  })

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const {oldPassword, newPassword} = req.body

  const user = await User.findById(req.user?._id)
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

  if(!isPasswordCorrect){
    throw new ApiError(400, "Invalid user Password")
  }

  user.password = newPassword
  await user.save({
    validateBeforeSave: false
  })


  return res
  .status(200)
  .json(new ApiResponse(
    200, {}, "Password Changed Successfully"
  ))

})

const getCurrentUser = asyncHandler(async(req, res) => {
  return res
  .status(200)
  .json(new ApiResponse(
      200,
      req.user,
      "User fetched successfully"
  ))
})

const updateAccountDetails = asyncHandler(async(req, res) => {
  const {fullName, email} = req.body

  if(!fullName || !email){
    throw new ApiError(400, "All fields are Required")
  }

  const user = User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullName: fullName,
        email: email
      }
    },

    {
      new: true
    }

  ).select("-password")

  return res
  .status(200)
  .json(
    new ApiResponse(200, user, "Account Details Updated Succesfully")
  )

})

const updateUserAvatar = asyncHandler(async(req, res) => {
  const avatarLocalPath = req.file?.path

  if(!avatarLocalPath){
    throw new ApiError(400, "Avatar file not available")
  }
  const avatar = await uploadOnCloudinary(avatarLocalPath)

  if(!avatar.url){
    throw new ApiError(400, "Avatar file not uploaded")
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set:{
        avatar: avatar.url
      }
    },
    {
      new: true
    }
  ).select("-password")

  return res
  .status(200)
  .json(new ApiResponse(
    200,
    user, 
    "Avatar updated Succesfully"
  ))
})


const updateUserCoverImage = asyncHandler(async(req, res) => {
  const coverImageLocalPath = req.file?.path

  if(!coverImageLocalPath){
    throw new ApiError(400, "Cover Image file not available")
  }

  const coverImage = await uploadOnCloudinary(coverImageLocalPath)

  if(!coverImage.url){
    throw new ApiError(400, "cover Image file not uploaded")
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set:{
        coverImage: coverImage.url
      }
    },
    {
      new: true
    }
  ).select("-password")

  return res
  .status(200)
  .json(new ApiResponse(
    200,
    user, 
    "cover Image updated Succesfully"
  ))
})

const getUserChannelProfile = asyncHandler(async (req, res) => {
  const {username} = req.params

  if(!username?.trim()){
    throw new ApiError(400, "username is missing")
  }

  const channel = await User.aggregate([
    {
      $match: {
        username: username?.trim()
      }
    },

    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers"
      }
    },

    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo"
      }
    },

    {
      $addFields: {
        subscribersCount: {
          $size: "subscribers"
        },

        channelsSubscribedToCount: {
          $size: "subscribedTo"
        },

        isSubscribed: {
          $cond: {
            if: {$in: [req.user?._id, "$subscribers.subscriber"]},
            then: true,
            else: false
          }
        }
      }
    },

    {
      $project: {
        fullName: 1,
        username: 1,
        subscribersCount: 1,
        channelsSubscribedToCount: 1,
        isSubscribed: 1,
        avatar: 1,
        coverImage: 1,
        email: 1
      }
    },


  ])

  if(!channel?.length){
    throw new ApiError(404, "Channel does not exist")
  }

  return res
  .status(200)
  .json(
    new ApiResponse(200,
      channel[0],
      "User Channel fetched Succesfully"
    )
  )

})

const getWatchHistory = asyncHandler(async(req, res) => {
  const user = await User.aggregate([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(req.user_id)
      }
    },

    {
      $lookup: {
        from: "videos",
        localField: "watchHistory",
        foreignField: "_id",
        as: "watchHistory",
        pipeline: [
          {
            $lookup: {
              from: "users",
              localField: "owner",
              foreignField: "_id",
              as: "owner",
              pipeline: [
                {
                  $project: {
                      fullName: 1,
                      username: 1,
                      avatar: 1
                  }
                }
              ]
            }
          },
          {
            $addFields: {
              owner: {
                $first: "$owner"
              }
            }
          }
        ]
      }
    }
  ])


  return res
  .status(200)
  .json(
    new ApiResponse(200, user[0].watchHistory, "Watch History fetched Succesfully")
  )

}) 

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory

}
