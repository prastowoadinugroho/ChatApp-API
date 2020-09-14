const bcrypt = require('bcryptjs');
const { UserInputError, AuthenticationError } = require('apollo-server');
const jwt = require('jsonwebtoken');
const { Op } = require('sequelize');

const { JWT_SECRET } = require('../config/env.json');
const { User } = require('../models');

module.exports = {
    Query: {
      getUsers: async (_, __, context) => {
        try {
          let user
          if(context.req && context.req.headers.authorization){
            const token = context.req.headers.authorization.split('Bearer ')[1]
            jwt.verify(token, JWT_SECRET, (err,decodedToken) => {
              if(err){
                throw new AuthenticationError('Unaunthenticated')
              }
              user = decodedToken
            })
          }

          const users = await User.findAll({
            where: { username: {[Op.ne]: user.username}}
          })
          return users;
        } catch (err) {
            console.log(err)
            throw err
        }
      },
      login: async(_, args) => {
        const { username, password } = args
        let errors = {}

        try {
          if(username.trim() === '') errors.username = 'username must not be empty'
          if(password.trim() === '') errors.password = 'password must not be empty'

          if (Object.keys(errors).length > 0){
            throw new UserInputError('bad input', { errors })
          }

          const user = await User.findOne({
            where: { username }
          })
          if(!user){
            errors.username = 'user not found'
            throw new UserInputError('user not found', { errors })
          }

          const correctPassword = await bcrypt.compare(password, user.password)

          if(!correctPassword){
            errors.password = 'password is incorrect'
            throw new AuthenticationError('password is incorrect', { errors })
          }

          const token = jwt.sign({
            username
          }, JWT_SECRET, { expiresIn: '1h' });

          return {
            ...user.toJSON(),
            createdAt: user.createdAt.toISOString(),
            token
          }

        } catch (err) {
          console.log(err)
          throw err
        }
      }
    },
    Mutation: {
      register: async (_, args) => {
        let {
          username,
          email,
          password,
          confirmPassword
        } = args
        let errors = {}
        try {
          //TODO Validate input
          if(email.trim() == '') errors.email = 'Email must not be empty'
          if(username.trim() == '') errors.username = 'Username must not be empty'
          if(password.trim() == '') errors.password = 'Password must not be empty'
          if(confirmPassword.trim() == '') errors.confirmPassword = 'Repeat password must not be empty'
          if(password !== confirmPassword) errors.confirmPassword = 'Passwords must match'

          //TODO Check username/email
          // const userByUsername = await User.findOne({ 
          //   where: {
          //     username
          //   }
          // })
          // const userByEmail = await User.findOne({ 
          //   where: {
          //     email
          //   }
          // })
          // if(userByUsername) errors.username = "Username is taken"
          // if(userByEmail) errors.email = "Email is taken"

          if(Object.keys(errors).length > 0){
            throw errors
          }
          //TODO Hash Password
          password = await bcrypt.hash(password, 6)

          //TODO Create User
          const user = await User.create({
            username,
            email,
            password
          })

          //TODO Return User
          return user

        } catch (error) {
          console.log(error)
          if (error.name === 'SequelizeUniqueConstraintError'){
            error.errors.forEach(
              (e) => (errors[e.path] = `${e.path} is already taken`)
            )
          } else if (error.name === 'SequelizeValidationError'){
            error.errors.forEach((e) => (errors
              [e.path] = e.message))
          }
          throw new UserInputError('Bad Input', {errors })
        }
      }
    }
};