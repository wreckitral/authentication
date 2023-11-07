const jwt = require("jsonwebtoken");

const authenticate = async (req, res, next) => {
    try {   
        const token = req.headers.authorization.split(" ")[1];

        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        
        req.user = decodedToken;
        next();

    } catch (error) {
        res.status(401).json({ error: "Authentication Failed"})
    }
}


const localVariables = (req, res, next) => {
    req.app.locals = {
        OTP: null,
        resetSession: false
    }

    next()
} 

module.exports = {
    authenticate, 
    localVariables
}