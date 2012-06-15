#!/usr/bin/env node

var express = require('express');
var app = express.createServer();
var staticDirectory = __dirname+"/../static";
console.log("static is "+staticDirectory);

app.use(express.logger("dev"));
app.use(express.static(staticDirectory));
app.get("/", function(req, res) { res.redirect("/index.html"); });

app.listen(8080);
