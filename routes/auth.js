const router = require("express").Router();
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const AWS = require("aws-sdk");

AWS.config.update({ region: 'ap-south-1' });
var credentials = new AWS.SharedIniFileCredentials({profile: 'default'}); 
AWS.config.credentials = credentials;

// validation
const { registerValidation, loginValidation } = require("../validation");

// encryption lib
const bcrypt = require("bcrypt");

function generateOTP() {
          
    // Declare a digits variable 
    // which stores all digits
    var digits = '0123456789';
    let OTP = '';
    for (let i = 0; i < 6; i++ ) {
        OTP += digits[Math.floor(Math.random() * 10)];
    }
    return OTP;
}


router.post("/register", async (req, res) => {
    // validate the user
    const { error } = registerValidation(req.body);

    if (error) {
        return res.status(400).json({ error: error.details[0].message });
    }

    const isEmailExist = await User.findOne({ email: req.body.email });

    if (isEmailExist) {
        return res.status(400).json({ error: "Email already exists" });
    }

    // hash the password
    const salt = await bcrypt.genSalt(10);
    const password = await bcrypt.hash(req.body.password, salt);

    // generate OTP

    let otpStr = generateOTP().toString();
    console.log(otpStr);

    //hash the OTP
    const otpSalt = await bcrypt.genSalt(10);
    const otp = await bcrypt.hash(otpStr, otpSalt);
    console.log("OTP is hashed -- ", otp);


    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password,
        verified: false,
        temp: otp,
    });

    try {
        const savedUser = await user.save();
        // Send the OTP in email

        // Create sendEmail params 
        params = {
            Destination: {
              /* required */
              CcAddresses: [
                /* more items */
              ],
              ToAddresses: [
                savedUser.email, //RECEIVER_ADDRESS
                /* more To-email addresses */
              ],
            },
            Message: {
              /* required */
              Body: {
                /* required */
                Html: {
                  Charset: "UTF-8",
                  Data: "HTML_FORMAT_BODY",
                },
                Text: {
                  Charset: "UTF-8",
                  Data: "TEXT_FORMAT_BODY",
                },
              },
              Subject: {
                Charset: "UTF-8",
                Data: "EMAIL_SUBJECT",
              },
            },
            Source: "shreyanshece1041@gmail.com", // SENDER_ADDRESS
            ReplyToAddresses: [
              /* more items */
            ],
          };
        
        // Create the promise and SES service object
        var sendPromise = new AWS.SES({apiVersion: '2010-12-01'}).sendEmail(params).promise();
        
        // Handle promise's fulfilled/rejected states
        sendPromise.then(
            function(data) {
            console.log(data.MessageId);
            }).catch(
            function(err) {
            console.error(err, err.stack);
            });

        //send response
        res.json({ 
                    error: null, 
                    data: { 
                            userId: savedUser._id, 
                            name: savedUser.name, 
                            email: savedUser.email
                          }, 
                    message: "Successfully registered, Please verify email address to be able to login"
                });
    }
    catch (error) {
        res.status(400).json({ error });
    }

});


// login route
router.post("/login", async (req, res) => {

    // validate the user
    const { error } = loginValidation(req.body);

    // throw validation errors
    if (error) return res.status(400).json({ error: error.details[0].message });

    const user = await User.findOne({ email: req.body.email });

    // throw error when email is wrong
    if (!user) return res.status(400).json({ error: "Email is wrong" });

    // check for password correctness
    const validPassword = await bcrypt.compare(req.body.password, user.password);

    if (!validPassword)
        return res.status(400).json({ error: "Password is wrong" });

    if (validPassword && !User.verified)
    {
        return res.status(400).json({ Message: "Please verify the email ID"});
    }

    // create token
    const token = jwt.sign(
        // payload data
        {
            name: user.name,
            id: user._id,
        },
        "Stack",
        {expiresIn: '2m'}, // expires in 2 min,
        process.env.TOKEN_SECRET
    );

    res.header("auth-token", token).json({
        error: null,
        id: user._id,
        name: user.name,
        email: user.email,
        data: {
            token,
        },
    });
});


module.exports = router;