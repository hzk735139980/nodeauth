var mysql      = require('mysql');
var connection = mysql.createConnection({
  host     : 'localhost',
  user     : 'root',
  password : '',
  database: 'my_schema'
});

connection.connect();

module.exports = connection;