const express = require("express");
const router = new express.Router();
const User = require('../models/user');
const ExpressError = require('../expressError');
const jwt = require('jsonwebtoken');
const { SECRET_KEY } = require('../config');

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post('/login', async (req, res, next) => {
    try{
        const { username, password } = req.body;
        if (await User.authenticate(username, password)){
            User.updateLoginTimestamp(username);
            const token = jwt.sign({user : username}, SECRET_KEY);
            return res.json({token});
        }
        throw new ExpressError('Unauthorized', 401);
    } catch (err) {
        return next(err);
    }
});


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async (req, res, next) => {
    try{
        const user = await User.register(req.body);
        User.updateLoginTimestamp(user.username);
        const token = jwt.sign({user : user.username}, SECRET_KEY);
        return res.json({token});
    } catch (err) {
        if (err.code === "23505") return next(new ExpressError('Username already exists', 400))
        return next(err);
    }
});

module.exports = router;