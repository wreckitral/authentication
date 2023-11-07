const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
const nodemailer = require("nodemailer");

/* registering user and then sending email confirmation link to user */
const register = async (req, res) => {
  try {
    const { firstName, lastName, username, email, password } = req.body;

    if (
      !firstName ||
      !lastName ||
      !username ||
      !email ||
      !password ||
      firstName === "" ||
      lastName === "" ||
      username === "" ||
      email === "" ||
      password === ""
    )
      return res.status(400).json({ msg: "All fields are required" });

    const existUsername = await User.findOne({ username: username });
    const existEmail = await User.findOne({ email: email });

    if (existUsername)
      return res.status(409).json({ msg: "Username already exist" });
    if (existEmail)
      return res.status(409).json({ msg: "Email already registered" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      firstName,
      lastName,
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();

    let config = {
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    };

    let transporter = nodemailer.createTransport(config);

    jwt.sign(
      { userId: newUser._id },
      process.env.EMAIL_SECRET,
      {
        expiresIn: "1d",
      },
      (err, emailToken) => {
        const url = `http://localhost:5000/confirmation/${emailToken}`;

        transporter.sendMail({
          to: newUser.email,
          subject: "Confirm Email",
          html: `Please click this email to confirm your email: <a href="${url}">click this</a>`,
        });
      }
    );

    return res.status(201).json({ msg: "We sent an email for verification." });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

/* controller for email confirmation endpoint */
const confirmation = async (req, res) => {
  try {
    const { userId } = jwt.verify(
      req.params.emailToken,
      process.env.EMAIL_SECRET
    );
    await User.updateOne({ _id: userId }, { isConfirmed: true });
    return res
      .status(201)
      .json({ msg: "Email is Confirmed, you can redirect to login page" });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

/* controller for login */
const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password || username === "" || password === "")
      return res.status(400).json({ msg: "All fields are required" });

    const user = await User.findOne({ username });

    if (!user)
      return res.status(400).json({ msg: "User is not signed up yet" });

    if (!user.isConfirmed || user.isConfirmed === "false")
      return res.status(400).json({ msg: "Email is not verified" });

    const isPassMatch = await bcrypt.compare(password, user.password);

    if (!isPassMatch)
      return res.status(400).json({ msg: "Invalid Credentials" });

    const token = jwt.sign(
      {
        userId: user._id,
        username: user.username,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    const refreshToken = jwt.sign(
      { username: user.username },
      process.env.REFRESH_SECRET,
      { expiresIn: "1d" }
    );

    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res
      .status(200)
      .json({ msg: "Login Successful", username: user.username, token });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

/* refresh the access token */
const refresh = (req, res) => {
  const cookies = req.cookies;

  if (!cookies?.jwt) return res.status(401).json({ msg: "Unauthorized" });

  const refreshToken = cookies.jwt;

  jwt.verify(
    refreshToken,
    process.env.REFRESH_SECRET,
    async (err, decoded) => {
      if (err) return res.status(403).json({ message: "Forbidden" });

      const foundUser = await User.findOne({
        username: decoded.username,
      }).exec();

      if (!foundUser) return res.status(401).json({ message: "Unauthorized" });

      const accessToken = jwt.sign(
        {
          userId: foundUser._id,
          username: foundUser.username,
        },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
      );

      res.json({ accessToken });
    }
  );
};

/* controller for logging out the user and clearing the cookie */
const logout = (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204);
  res.clearCookie('jwt', {
    httpOnly: true,
    sameSite: 'None',
    secure: true
  })
  res.json({ msg: "Cookie cleared "})
}

/* getting the user  */
const getUser = async (req, res) => {
  try {
    const { username } = req.params;

    const user = await User.findOne({ username }, { password: 0 })
      .lean()
      .exec();

    if (!user) return res.status(404).json({ msg: "User Not Found" });

    return res.status(200).json(user);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

/* Update the user  */
const updateUser = async (req, res) => {
  try {
    const { userId } = req.user;

    if (userId) {
      const body = req.body;

      await User.updateOne({ _id: userId }, body);

      const updatedUser = await User.findOne({ _id: userId }, { password: 0 })
        .lean()
        .exec();

      return res.status(201).json(updatedUser);
    }
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

/* generate the OTP */
const generateOTP = (req, res) => {
  req.app.locals.OTP = otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });

  return res.status(201).json({ code: req.app.locals.OTP });
};

/* verifying otp  */
const verifyOTP = (req, res) => { 
  const { code } = req.query;
  if (parseInt(req.app.locals.OTP) === parseInt(code)) {
    req.app.locals.OTP = null; // reset OTP value
    req.app.locals.resetSession = true; // start session for reset password
    return res.status(201).json({ msg: "Verify Successfully" });
  }

  return res.status(400).json({ error: "Invalid OTP" });
};

const createResetSession = (req, res) => {
  if (req.app.locals.resetSession) {
    req.app.locals.resetSession = false;
    return res.status(201).json({ msg: "Access granted" });
  }
  return res.status(440).json({ error: "Session expired" });
};

/* this is the controller for resetting the password by sending email to the user */
const resetPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || email === "")
      return res.status(400).json({ msg: "Please input the Email" });

    const user = await User.findOne({ email }, { password: 0 });

    if (!user)
      return res.status(404).json({ msg: "Email is not registered yet" });

    let config = {
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    };

    let transporter = nodemailer.createTransport(config);

    jwt.sign(
      {
        userId: user._id,
      },
      process.env.PASSWORD_SECRET,
      { expiresIn: "1d" },
      (err, token) => {
        const url = `http://localhost:5000/reset-password/${user.id}/${token}`;

        transporter.sendMail({
          to: user.email,
          subject: "Change password",
          html: `Please click this link to change you password <a href="${url}">click this</a>`,
        });
      }
    );

    return res.status(200).json({
      msg: "password can be changed now, please click link that has been sent to you",
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

/* this is controller to confirm reset password */
const confirmResetPass = async (req, res) => {
  const { userId } = jwt.verify(req.params.token, process.env.PASSWORD_SECRET);

  const user = await User.findOne({ _id: userId });

  if (!user) return res.status(404).json({ msg: "User does not exist" });

  return res.status(200).json({
    msg: "Reset password token is confirmed, redirect to reset password endpoint",
  });
};

const chagePass = async (req, res) => {
  const { token } = req.params;
  const { password, newPassword } = req.body;
  const { userId } = jwt.verify(token, process.env.PASSWORD_SECRET);

  const user = await User.findOne({ _id: userId });

  if (!user) return res.status(404).json({ msg: "User does not exist" });

  const isPasswordMatch = await bcrypt.compare(password, user.password);

  if (!isPasswordMatch) return res.status(400).json({ msg: "Wrong password" });

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  await user.updateOne({ password: hashedPassword });

  return res.status(201).json({ msg: "Password reset successfully" });
};


/* this is controller for resetting password using session */
// const resetPassword = async (req, res) => {
//   try {
//     if (!req.app.locals.resetSession)
//       return res.status(440).json({ msg: "Session Expired" });

//     const { username, password } = req.body;

//     try {
//       const user = await User.findOne({ username }).exec();

//       if (!user) return res.status(404).json({ msg: "Username Not Found" });

//       const hashedPassword = await bcrypt.hash(password, 10);

//       await user.updateOne({ password: hashedPassword });

//       return res.status(201).json({ msg: "Password changed successfully" });
//     } catch (error) {
//       return res.status(500).json({ error: error.message });
//     }
//   } catch (error) {
//     return res.status(401).json({ error: error.message });
//   }
// };

module.exports = {
  register,
  login,
  getUser,
  updateUser,
  generateOTP,
  verifyOTP,
  createResetSession,
  resetPassword,
  confirmation,
  confirmResetPass,
  chagePass,
  logout,
  refresh   
};
