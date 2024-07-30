<?php
class db
{
    // Properties
    private $host = 'localhost';
    private $user = 'root';
    private $password = '';
    private $dbname = 'my_database';


    // Connect
    function connect()
    {
        $mysql_connect_str = "mysql:host=$this->host;dbname=$this->dbname";
        $dbConnection = new PDO($mysql_connect_str, $this->user, $this->password);
        $dbConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $dbConnection;
    }
}
