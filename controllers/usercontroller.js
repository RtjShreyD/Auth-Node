const User = require("../models/User");
const jwt = require("jsonwebtoken");

const nodemailer = require("nodemailer");

const utility = require("./utility");

var mail = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'shreyanshece1041@gmail.com',
        pass: 'lwlymzpjnxfnflul'
    }
})

// validation
const { registerValidation, loginValidation, otpValidation, passwordEmailValidation } = require("../validation");

// encryption lib
const bcrypt = require("bcrypt");

const createPerson = async (req, res) => {
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

    let otpStr = utility.generateOTP().toString();
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

        var mailOptions = {
            from: 'shreyanshece1041@gmail.com',
            to: savedUser.email,
            subject: 'OTP for verification',
            text: otpStr
          };

          console.log(mailOptions);
          
          mail.sendMail(mailOptions, function(error, info){
            if (error) {
              console.log(error);
            } else {
              console.log('Email sent: ' + info.response);
            }
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
};


const verifyPerson = async (req, res) => {
    console.log(req.body)

    const { error } = otpValidation(req.body);
    // throw validation errors
    if (error) return res.status(400).json({ error: error.details[0].message });

    const user = await User.findOne({ email: req.body.email });

     // throw error when email is wrong
     if (!user) return res.status(400).json({ error: "Email is wrong" });
     console.log(user);
     // check for otp and verify status true

     if(user.verified) return res.status(201).json({ message: "Already verified user"});

     const validotp = await bcrypt.compare(req.body.oneTimePassword, user.temp)

     if(!validotp) return res.status(400).json({ error: "OTP does not match"});

    user.verified = true;
    user.temp = "";
    
    try {
        const savedUser = await user.save();
        return res.status(201).json({ success: "Email verified successfully", data:{name: savedUser.name, email: savedUser.email}});
    }
    catch (error) {
        res.status(400).json({ error });
    }    
};

const loginPerson = async (req, res) => {
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

    if (validPassword && !user.verified)
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
}

const passwordReset = async (req, res) => {
    const { error } = passwordEmailValidation(req.body);

    if (error) return res.status(400).json({ error: error.details[0].message });

    const user = await User.findOne({ email: req.body.email });

    // throw error when email is wrong
    if (!user) return res.status(400).json({ error: "Email is wrong" });

    if(!req.body.password === req.body.confirmPassword)
        return res.status(400).json({ error: "Password and confirmPassword do not match"});
    
    const salt = await bcrypt.genSalt(10);
    const newpassword = await bcrypt.hash(req.body.password, salt);

    user.password = newpassword;


    try {
        const savedUser = await user.save();
        return res.status(201).json({ success:"Password reset successfully", data: {id: savedUser._id, name: savedUser.name, email: savedUser.email }})
    }
    catch(error){
        return res.status(400).json({ error });   
    }

}


module.exports = { createPerson, verifyPerson, loginPerson, passwordReset };