const register =require('../Models/Register');
const bcrypt =require('bcrypt');
const express= require('express');
const Router = express.Router();
const asyncvalidator =require('../Middleware/Async');
const jwt = require("jsonwebtoken");
const { check, validationResult } = require('express-validator');
const myvalidationResult = validationResult.withDefaults({
    formatter: (error) => {
        return {
            msg: error.msg,
        };
    }
});
/**
 * @swagger
 *
 * /api/users:
 *   get:
 *     description:  get all users details
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: get all users details
 */
Router.get('/',asyncvalidator(async (req,res)=>{
    const reg = await register.find();
    res.send(reg);
}));
/**
 * @swagger
 *
 * /api/users:
 *   post:
 *     description: Registers user to the application
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: name
 *         description: Username
 *         in: formData
 *         required: true
 *         type: string
 *       - name: email
 *         description: email
 *         in: formData
 *         required: true
 *         type: string
 *       - name: password
 *         description: password
 *         in: formData
 *         required: true
 *         type: string
 *       - name: confirmPassword
 *         description: confirm Password
 *         in: formData
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Registers a user
 */
Router.post('/',[
    check('email','Email is Required').isEmail(),
    check('name','username should have min. 5 characters').isLength({min:5}),
    check('password','password must be min. 6 characters.').isLength({min:6}),
    check('confirmPassword',' confirm password must be min. 6 characters.').isLength({min:6})
],asyncvalidator(async (req,res)=>{
    const errors = myvalidationResult(req);
    if(!errors.isEmpty()) return res.status(422).json(errors.array() );
    let user = await register.findOne({email:req.body.email});
    if(user) return res.status(400).send([{msg:"Already have account"}]);

    user= new register({
        name:req.body.name,
        email:req.body.email,
        password:req.body.password,
        confirmPassword:req.body.confirmPassword
    });
    if(req.body.password !==req.body.confirmPassword) return res.status(400).send([{msg:"confirm password does not match"}]);
    const salt =await bcrypt.genSalt(5);
    user.password =await bcrypt.hash(user.password ,salt);
    const salt1 =await bcrypt.genSalt(5);
    user.confirmPassword =await bcrypt.hash(user.confirmPassword ,salt1);
    await user.save();
    const token = jwt.sign({id: user._id,name:user.name},process.env.PRIVATEKEY);
    res.send({token:token});
}));

/**
 * @swagger
 *
 * /api/users/{id}:
 *   get:
 *     description: get user details by id
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         in: path
 *     responses:
 *       200:
 *         description: get user details by id
 */
Router.get('/:id', asyncvalidator(async (req, res) => {
    const reg = await register.findById(req.params.id);
    if (!reg) return res.status(404).send('The account with the given ID was not found.');
    res.send(reg);
}));

/**
 * @swagger
 *
 * /api/users/{id}:
 *   put:
 *     description: update user data by id
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         in: path
 *       - name: email
 *         description: email
 *         in: formData
 *         required: true
 *         type: string
 *       - name: name
 *         description: name
 *         in: formData
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: update user data by id
 */
Router.put('/:id',[
    check('email','Email is Required').isEmail(),
    check('name','username should have min. 5 characters').isLength({min:5}),
    check('password','password must be min. 6 characters.').isLength({min:6}),
    check('confirmPassword',' confirm password must be min. 6 characters.').isLength({min:6})
],asyncvalidator( async (req, res) => {
    const errors = myvalidationResult(req);
    if(!errors.isEmpty()) return res.status(422).json(errors.array());
    const reg = await register.findByIdAndUpdate(req.params.id,{name:req.body.name,email:req.body.email},{
        new: true
    });
    if (!reg) return res.status(404).send('The account with the given ID was not found.');
    res.send(reg);
}));

/**
 * @swagger
 *
 * /api/users/{id}:
 *   delete:
 *     description: update user data by id
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         in: path
 *     responses:
 *       200:
 *         description: update user data by id
 */
Router.delete('/:id',asyncvalidator( async (req, res) => {
    const reg = await register.findByIdAndRemove(req.params.id);
    if (!reg) return res.status(404).send('The account with the given ID was not found.');
    res.send("account deleted");
}));

module.exports=Router;
