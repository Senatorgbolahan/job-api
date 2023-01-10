const User = require('../models/User')
const { StatusCodes } = require('http-status-codes')
const { BadRequestError, UnauthenticatedError } = require('../errors')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')


// *************************************** Register User
const register = async(req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        throw new BadRequestError('Please provide name, email abd password')
    }

    // hash user's password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt)

    const tempUser = { name, email, password: hashedPassword }

    // save user into mongoose database
    const user = await User.create({...tempUser })
    const token = jwt.sign({ userId: user._id, name: user.name }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_LIFETIME })


    res.status(StatusCodes.CREATED).json({ user: { name: user.name }, token })
}

// *************************************** Login User
const login = async(req, res) => {
    const { email, password } = req.body

    if (!email || !password) {
        throw new BadRequestError("Please provide email and password")
    }

    // check if email exists in database
    const user = await User.findOne({ email })
    if (!user) {
        throw new UnauthenticatedError("Invalid Credentials")
    }

    // compare password
    const isPasswordCorrect = bcrypt.compare(password, user.password)
    if (!isPasswordCorrect) {
        throw new UnauthenticatedError('Password Invalid Credentials')
    }


    const token = user.createJWT()
    res.status(StatusCodes.OK).json({ user: { name: user.name }, token })

}


module.exports = {
    register,
    login,
}