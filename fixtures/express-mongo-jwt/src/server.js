const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const { ApolloServer } = require("apollo-server-express");
const { typeDefs, resolvers } = require("./graphql");
const auth = require("./middleware/auth");

const app = express();
app.use(cors());
app.use(cookieParser());
app.use(express.json({ limit: "100mb" }));
app.use(express.static("public"));

app.use("/api/auth", require("./routes/auth"));
app.use("/api/users", require("./routes/users"));
app.use("/api/webhooks", require("./routes/webhooks"));
app.use(auth);
app.use("/api/files", require("./routes/files"));
app.use("/api/import", require("./routes/import"));
app.use("/api/admin", require("./routes/admin"));

const apollo = new ApolloServer({ typeDefs, resolvers, introspection: true, playground: true });
apollo.start().then(() => apollo.applyMiddleware({ app }));

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

mongoose.connect(process.env.MONGO_URL);
app.listen(process.env.PORT || 4000);
