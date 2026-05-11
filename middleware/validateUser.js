/** HTTP Request validators 
This component contains Express middleware that validates incoming requests
They are used by the routes */

const {isValidEmail, isValidPassword} = require("../utils/authValidator");

/*  Validate user registration data from request body
    Checks:
        - Email is valid format
        - Password meets strength requirements
    Usage: router.post('/', validateRegistration, registerUser);
*/

function validateRegistration(req, res, next)
{
    const {email, password} = req.body;

    const emailResult = isValidEmail(email);
    if (!emailResult.valid)
    {
        return res.status(400).json({error: emailResult.reason});
    }

    req.body.email = emailResult.normalised;

    const passwordResult = isValidPassword(password);
    if (!passwordResult.valid)
    {
        return res.status(400).json({error: passwordResult.reason});
    }

    next();
}

/*  Validate user login data from request body
    Checks:
        - Email and password are provided by user
        - Email and password are within length limits
    Usage: router.post('/', validateLogin, loginUser);
*/
function validateLogin(req, res, next)
{
    const {email, password} = req.body;

    if (!email || !password)
    {
        return res.status(400).json({error: "Email and password required"});
    }

    if (email.length > 255 || password.length > 128)
    {
        return res.status(400).json({error: "Input too long"});
    }

    const emailResult = isValidEmail(email);
    req.body.email = emailResult.normalised;

    next();
}

module.exports = {validateRegistration,
                  validateLogin}