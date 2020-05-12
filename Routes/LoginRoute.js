const bcrypt =require('bcrypt');
const express= require('express');
const Router = express.Router();
const register =require('../Models/Register');
const asyncvalidator =require('../Middleware/Async');
const jwt = require("jsonwebtoken");
const { check, validationResult } = require('express-validator');
const myValidationResult = validationResult.withDefaults({
    formatter: (error) => {
        return {
            msg: error.msg,
        };
    }
});
/**
 * @swagger
 *
 * /login:
 *   post:
 *     description: Login to the application
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: email
 *         description: Username to use for login.
 *         in: formData
 *         required: true
 *         type: string
 *       - name: password
 *         description: User's password.
 *         in: formData
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: login
 */
Router.post('/',
    [
        check('email','Email is Required').isEmail(),
        check('password',).isLength({min:6}).withMessage('password must be min. 6 characters.')
    ],asyncvalidator(async (req,res)=>{
        const errors = myValidationResult(req);
    if(!errors.isEmpty()) return res.status(422).json(errors.array() );
    let user = await register.findOne({email:req.body.email});
    if(!user) return res.status(400).send([{msg:"invalid email or password"}]);
    const valid= await  bcrypt.compare(req.body.password ,user.password);
    if(!valid) return res.status(400).send([{msg:"invalid email or password"}]);
    const token =jwt.sign({id: user._id,name:user.name},process.env.PRIVATEKEY);
        res.send({token:token});
}));
module.exports=Router;
