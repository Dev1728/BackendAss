import {Router} from 'express'
import { registerUser,loginUser,logOut,refershedAceessToken,forgotPassword,resetPassword} from '../controllers/user.controller.js';
import { verifyJWT } from '../middlewares/auth.middleware.js';
const router= Router();


router.route("/register").post(registerUser)
router.route("/login").post(loginUser)

//secured Routes
router.route("/logout").post(verifyJWT,logOut)
router.route("/refresh-token").post(refershedAceessToken)

router.route("/forget-password").post(forgotPassword)
router.route("/reset-password/:token").post(resetPassword)

export default router;