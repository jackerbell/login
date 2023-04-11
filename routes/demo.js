const express = require('express');
const bcrypt = require('bcryptjs');

const db = require('../data/database');
const { json } = require('express');

const router = express.Router();

router.get('/', function (req, res) {
  res.render('welcome');
});

router.get('/signup', function (req, res) {
  let sessionInputData = req.session.inputData;
  
  if(!sessionInputData){
    sessionInputData = {
      hasError:false,
      email:'',
      confirmEmail:'',
      password:''
    };
  }

  req.session.inputData = null;

  res.render('signup',{inputData:sessionInputData});
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
      req.session.inputData = {
        hasError : true,
        message : 'Invalid input - please check your data.',
        email: enteredEmail,
        confirmEmail: enteredConfirmEmail,
        password: enteredPassword
      };

      req.session.save(()=>{
        return res.redirect('/signup');
      });
      return;
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
    res.redirect('/profile');
  })
});

router.get('/admin', function (req, res) {
  if(!req.session.isAuthenticated){ // !req.session.user 로 대체 가능
    return res.status(401).render('401');
  }
  console.log(req.session.user.id);

  const user = db.getDb().collection('users').findOne({_id:req.session.user.id});

  if(!user || !user.isAdmin){
    return res.status(403).render('403');
  }

  res.render('admin');
});

router.get('/profile', function (req, res) {
  if(!req.session.isAuthenticated){ // !req.session.user 로 대체 가능
    return res.status(401).render('401');
  }
  res.render('profile');
});

router.post('/logout', function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect('/');
});

module.exports = router;
