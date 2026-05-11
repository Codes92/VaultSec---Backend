/** This file contains the code for checking a user's login status */

const jwt = require("jsonwebtoken");

function isLoggedIn(req, res, next)
{
    const token = req.cookies.token;
    if(!token)
    {
        return res.status(401).json({error: "No token provided"});
    }

    try
    {
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach user data to request
        next();
    } 
    catch (err)
    {
        if (err.name === "TokenExpiredError")
        {
            return res.status(401).json({error: "Token expired"});
        }
        return res.status(401).json({error: "Invalid token"});
    }
}

module.exports = {isLoggedIn};