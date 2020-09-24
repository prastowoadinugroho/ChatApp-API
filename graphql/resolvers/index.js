const userResolvers = require('./users');
const messagesResolvers = require('./messages');

module.exports = {
    Message: {
        createdAt: (parent) => parent.createdAt.toISOString()
    },
    Query: {
        ...userResolvers.Query,
        ...messagesResolvers.Query
    },
    Mutation: {
        ...userResolvers.Mutation,
        ...messagesResolvers.Mutation
    }
}