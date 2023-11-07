const { Router } = require("express");
const router = Router();
const appController = require("../controllers/appController");
const { authenticate, localVariables } = require("../middlewares/authenticate");
const registerMail = require("../controllers/mailer");

// POST Method
router.post("/register", appController.register);
router.post("/register-email", registerMail);
router.post("/login", appController.login);
router.post("/reset-password", appController.resetPassword);
router.post("/logout", appController.logout);

// GET Method
router.get("/user/:username", appController.getUser);
router.get("/generate-OTP", localVariables, appController.generateOTP);
router.get("/verify-OdTP", appController.verifyOTP);
router.get("/confirmation/:emailToken", appController.confirmation); //frontend endpoint
router.get("/reset-password/:id/:token", appController.confirmResetPass); // frontend endpoint
router.get("/reset-session", appController.createResetSession);
router.get("/refresh", appController.refresh);

// PATCH Method
router.patch("/update-user", authenticate, appController.updateUser);
router.patch("/reset-password/:id/:token", appController.chagePass);

module.exports = router;
