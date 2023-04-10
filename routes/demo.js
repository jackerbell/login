const express = require('express');
const bcrypt = require('bcryptjs');

const db = require('../data/database');
const { json } = require('express');

const router = express.Router();

router.get('/', function (req, res) {
  res.render('welcome');
});

router.get('/signup', function (req, res) {
  res.render('signup');
});

router.get('/login', function (req, res) {
  res.render('login');
});

router.post('/signup', async function (req, res) {
  const userData = req.body; // app.js에서 urlencoded 미들웨어에 의해 해석
  const enteredEmail = userData.email;
  const enteredConfirmEmail = userData['confirm-email'];
  const enteredPassword = userData.password;

  if(
    !enteredEmail || 
    !enteredConfirmEmail || 
    !enteredPassword || 
    enteredPassword.trim() < 6 || 
    enteredEmail !== enteredConfirmEmail || 
    !enteredEmail.includes('@')){
      console.log('Incorrect data');
      return res.redirect('/signup');
  }

  const existingUser = await db
    .getDb()
    .collection('users')
    .findOne({email:enteredEmail});

  if(existingUser) {
    console.log('User exists already');
    return res.redirect('/signup');
  }

  const hashedPassword = await bcrypt.hash(enteredPassword, 12);

  const user = {
    email : enteredEmail,
    password : hashedPassword
  };

  await db.getDb().collection('users').insertOne(user);

  res.redirect('/login');
});

router.post('/login', async function (req, res) {
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredPassword = userData.password;

  const existingUser = await db
    .getDb()
    .collection('users')
    .findOne({email: enteredEmail}); 

   if(!existingUser) {
    console.log('could not login!');
    return res.redirect('/login');
   }
   
  const passwordsAreEqual =  await bcrypt.compare(
    enteredPassword, 
    existingUser.password
  ); // 비교 결고로 불린 값이 할당됨. 

  if(!passwordsAreEqual) {
    console.log('Could not log in - passwords are not equal!');
    return res.redirect('/login');
  }

  req.session.user = { id:existingUser._id, email:existingUser.email};
  req.session.isAuthenticated = true;
  req.session.save(()=>{
    res.redirect('/admin');
  })
});

router.get('/admin', function (req, res) {
  //Check the user "ticket"!
  res.render('admin');
});

router.post('/logout', function (req, res) {});

module.exports = router;
