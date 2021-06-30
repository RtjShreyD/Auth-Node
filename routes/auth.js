const router = require("express").Router();

const {createPerson, verifyPerson, loginPerson} = require('../controllers/usercontroller')

router.post("/register", createPerson);


router.post('/verify-otp', verifyPerson);

// login route
router.post("/login", loginPerson);


module.exports = router;