const express = require("express");
const router = new express.Router();
const User = require('../models/user');
const ExpressError = require('../expressError');
const auth = require('../middleware/auth');
const { SECRET_KEY } = require('../config');

/** GET / - get list of users.
 *
 * => {users: [{username, first_name, last_name, phone}, ...]}
 *
 **/

router.get('/', auth.ensureLoggedIn, async (req, res, next) => {
    try{
        const users = await User.all();
        return res.json({users});
    } catch (err) {
        return next(err);
    }
});


/** GET /:username - get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 *
 **/

router.get('/:username', auth.ensureCorrectUser, async (req, res, next) => {
    try{
        const user = await User.get(req.params.username);
        return res.json({user});
    } catch (err) {
        return next(err);
    }
});


/** GET /:username/to - get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get('/:username/to', auth.ensureCorrectUser, async (req, res, next) => {
    try{
        const messages = await User.messagesTo(req.params.username);
        return res.json({messages});
    } catch (err) {
        return next(err);
    }
});


/** GET /:username/from - get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get('/:username/from', auth.ensureCorrectUser, async (req, res, next) => {
    try{
        const messages = await User.messagesFrom(req.params.username);
        return res.json({messages});
    } catch (err) {
        return next(err);
    }
})


module.exports = router;