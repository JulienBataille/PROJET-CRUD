const express = require('express');
const User = require('../models/user');
const authentification = require ('../middlewares/authentification');
const router = new express.Router();

router.post('/users', async (req, res, next) =>{
    const user = new User(req.body);
    try{
        const authToken = await user.generateAuthTokenAndSaveUser();
        res.status(201).send({user, authToken});
    } catch (e){
        res.status(400).send(e);
    }
});

router.post('/users/login', async (req,res) => {
    try {
        const user = await User.findUser(req.body.email, req.body.password);
        const authToken = await user.generateAuthTokenAndSaveUser();
        res.send({user, authToken});
    } catch (e){
        res.status(400).send()
    }
});

router.post('/users/logout', authentification ,async (req,res) => {
    try {
        req.user.authTokens = req.user.authTokens.filter((authToken) =>{
        return authToken.authToken !== req.authToken;
    });

    await req.user.save()
    res.send()
    } catch (e){
        res.status(500).send();
    }
});

router.post('/users/logout/all', authentification ,async (req,res) => {
    try {
        req.user.authTokens = [];
        await req.user.save()
        res.send()
    } catch (e){
        res.status(500).send();
    }
});

router.get('/users/me', authentification , async (req,res, next) => {
    res.send(req.user)
});

router.patch('/users/me',authentification , async (req,res, next) => {
    const updateInfo = Object.keys(req.body);
    try{
        updateInfo.forEach(update => req.user[update] = req.body[update])
        await req.user.save();

        res.send(req.user);
    } catch(e) {
        res.status(500).send(e);
    }

})

router.delete('/users/me', authentification, async (req, res, next) => {
    try {
        await req.user.deleteOne();
        res.send(req.user);
    } catch (e) {
        res.status(500).send();
    }
});





module.exports = router