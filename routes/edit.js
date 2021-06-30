const router = require("express").Router();

const {passwordReset} = require('../controllers/usercontroller')

router.post('/reset-password', passwordReset);

module.exports = router;