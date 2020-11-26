const passport = require('passport');
const bcrypt = require('bcryptjs');
const db = require('./db');
const LocalStrategy = require('passport-local').Strategy

const checkPass = async (provided, userPass)=>bcrypt.compare(provided, userPass);

const local = function(email, pass, done) {
    db.users.findOne({ email })
    .then(user=>{
        if(!user) return done(null, false)
        checkPass(pass, user.pass)
            .then(bool=>done(null, bool?{...user, pass: 'hidden'}:false))
            .catch(done)
    })
    .catch(done)
}


passport.use(new LocalStrategy(local));

passport.serializeUser(function(user, done) {
    done(null, JSON.stringify(user));
});
   
passport.deserializeUser(function(user, done) {
    done(null, JSON.parse(user));
});

module.exports = {
    checkPass,
    hash: pass=>bcrypt.hash(pass, process.env.HASH_ROUNDS*1||8),
    login: (email, pass)=>new Promise((res, rej)=>local(email, pass, (err, user)=>{ (err||!user)?rej(err):res(user) })),
    onlyLogged: (req, res, next)=>{ if(!req.user) return res.redirect('/login'); next(); }
}