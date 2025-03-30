import {Router} from 'express'
import { loginUser,logOut,refershedAceessToken, createProfile, updateProfile, viewUserProfile} from '../controllers/user.controller.js';
import { verifyJWT } from '../middlewares/auth.middleware.js';
const router= Router();


router.route("/create").post(createProfile)
router.route("/login").post(loginUser)

//secured Routes
router.route("/logout").post(verifyJWT,logOut)
router.route("/refresh-token").post(refershedAceessToken)

router.route("/update/:profileId").put(updateProfile)
router.route("/view/:profileId").get(viewUserProfile)

export default router;