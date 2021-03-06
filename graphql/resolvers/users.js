const bcrypt = require('bcryptjs');
const { UserInputError, AuthenticationError } = require('apollo-server');
const jwt = require('jsonwebtoken');
const { Op } = require('sequelize');

const { JWT_SECRET } = require('../../config/env.json');
const { Message, User } = require('../../models');

module.exports = {
    Query: {
      getUsers: async (_, __, { user }) => {
        try {
          if(!user) throw new AuthenticationError('Unauthenticated');

          let users = await User.findAll({
            attributes: ['username', 'imageUrl','createdAt'],
            where: { username: {[Op.ne]: user.username}}
          })

          const allUserMessages = await Message.findAll({
            where: {
              [Op.or]: [{ from: user.username }, { to: user.username }]
            },
            order: [['createdAt', 'DESC']]
          })

          users = users.map(otherUser => {
            const latestMessage = allUserMessages.find(
              m => m.from === otherUser.username || m.to === otherUser.username
            )
            otherUser.latestMessage = latestMessage
            return otherUser
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
            throw new UserInputError('password is incorrect', { errors })
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
      },
    }
};