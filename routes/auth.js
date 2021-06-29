const router = require("express").Router();
const User = require("../models/User");

// validation
const { registerValidation } = require("../validation");

// encryption lib
const bcrypt = require("bcrypt");

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

    const user = new User({
    name: req.body.name,
    email: req.body.email,
    password,
  });

  try 
  {
    const savedUser = await user.save();
    res.json({ error: null, data: { userId: savedUser._id } });
  } 
  catch (error) 
  {
    res.status(400).json({ error });
  }

});

module.exports = router;