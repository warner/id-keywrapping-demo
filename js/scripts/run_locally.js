#!/usr/bin/env node

var express = require('express');
var app = express.createServer();
var staticDirectory = __dirname+"/../static";
console.log("static is "+staticDirectory);

app.use(express.logger("dev"));
app.use(express.static(staticDirectory));
app.use(express.bodyParser());
app.get("/", function(req, res) { res.redirect("/index.html"); });
app.post("/scrypt", function(req, res) {
             console.log(req.body.A_hex);
             setTimeout(function() {res.json({B_hex: "abcdef1234"})},
                        2000);
             });

app.listen(8080);
