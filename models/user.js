/** User class for message.ly */
const db = require('../db');
const bcrypt = require('bcrypt');
const { BCRYPT_WORK_FACTOR } = require('../config');
const ExpressError = require('../expressError');


/** User of the site. */

class User {

  /* validates presence of object properties
  *  returns 400 ExpressError if missing
  */

  static validateArgs(obj){
    for (let arg in obj){
      if (obj[arg] === undefined) throw new ExpressError(`Missing field: ${arg}`, 400);
    }
  }

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}){
    User.validateArgs({username, password, first_name, last_name, phone});
    const hashedPass = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(`
      INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPass, first_name, last_name, phone, new Date(), new Date()]);
    
    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    User.validateArgs({username, password});
    const result = await db.query('SELECT password FROM users WHERE username = $1', [username]);
    console.log(result);
    if (result.rowCount < 1) throw new ExpressError('User not found', 404);

    const user = result.rows[0];
    return await bcrypt.compare(password, user.password);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    User.validateArgs({username});
    const result = await db.query(
      `UPDATE users SET last_login_at = $1 WHERE username = $2
      RETURNING *`, [new Date(), username]);
    if (result.rowCount < 1) throw new ExpressError('User not found', 404);
    console.log(result.rows[0]);
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    );
    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    User.validateArgs({username});
    const result = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users
      WHERE username = $1`, [username]
    );
    if (result.rowCount < 1) throw new ExpressError('User not found', 404);
    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    User.validateArgs({username});
    const result = await db.query(
      `SELECT messages.id, messages.body, messages.sent_at, messages.read_at,
      to_user.username, to_user.first_name, to_user.last_name, to_user.phone
      FROM messages
      JOIN users from_user ON messages.from_username = from_user.username
      JOIN users to_user ON messages.to_username = to_user.username
      WHERE from_user.username = $1`, [username]
    );
    if (result.rowCount < 1) throw new ExpressError('No messages found', 404);
    // Destructure each row's fields into message object, and nested to_user object
    const resArr = result.rows.map(({username, first_name, last_name, phone, id, body, sent_at, read_at}) => {
      const to_user = {username, first_name, last_name, phone};
      return {id, body, sent_at, read_at, to_user};
    });
    return resArr;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    User.validateArgs({username});
    const result = await db.query(
      `SELECT messages.id, messages.body, messages.sent_at, messages.read_at,
      from_user.username, from_user.first_name, from_user.last_name, from_user.phone
      FROM messages
      JOIN users from_user ON messages.from_username = from_user.username
      JOIN users to_user ON messages.to_username = to_user.username
      WHERE to_user.username = $1`, [username]
    );
    if (result.rowCount < 1) throw new ExpressError('No messages found', 404);
    // Destructure each row's fields into message object, and nested to_user object
    const resArr = result.rows.map(({username, first_name, last_name, phone, id, body, sent_at, read_at}) => {
      const from_user = {username, first_name, last_name, phone};
      return {id, body, sent_at, read_at, from_user};
    });
    return resArr;
  }
}


module.exports = User;