const { gql } = require("apollo-server-express");
const Note = require("./models/Note");

const typeDefs = gql`
  type Note { id: ID!, text: String!, owner: String! }
  type Query { notes: [Note!]! }
`;

const resolvers = {
  Query: {
    notes: () => Note.find({}),
  },
};

module.exports = { typeDefs, resolvers };
