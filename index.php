<?php
use Slim\Factory\AppFactory;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: X-Requested-With, Content-Type, Accept, Origin, Authorization");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");

require 'vendor/autoload.php';
require_once './config.php';

// Instantiate db class
$db = new db();

// Create Slim app
$app = AppFactory::create();
$app->addRoutingMiddleware();
$errorMiddleware = $app->addErrorMiddleware(true, true, true);

// User Registration
$app->post('/users', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody();
    $name = filter_var($data['name'], FILTER_SANITIZE_STRING);
    $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
    $password = password_hash($data['password'], PASSWORD_DEFAULT);

    try {
        $conn = $db->connect();
        $sql = "INSERT INTO users (name, email, password) VALUES (:name, :email, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $password);
        $stmt->execute();
        $userId = $conn->lastInsertId();
        $conn = null;

        $response->getBody()->write(json_encode(['id' => $userId, 'name' => $name, 'email' => $email]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
    } catch (PDOException $e) {
        $error = ['error' => 'Database error: ' . $e->getMessage()];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

// User Login
$app->get('/users', function (Request $request, Response $response) use ($db) {
    $params = $request->getQueryParams();
    $email = filter_var($params['email'], FILTER_SANITIZE_EMAIL);
    $password = $params['password'];

    try {
        $conn = $db->connect();
        $sql = "SELECT * FROM users WHERE email = :email";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':email', $email);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $conn = null;
        
        if ($user && password_verify($password, $user['password'])) {
            unset($user['password']); // Do not return the password hash
            $response->getBody()->write(json_encode([$user]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
        } else {
            $response->getBody()->write(json_encode(['error' => 'Invalid email or password']));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(['error' => 'Database error: ' . $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

// Get all restaurants
$app->get('/restaurants', function ($request, $response) use ($db) {
    error_log("Reached the /restaurants route"); // Debugging output
    try {
        $conn = $db->connect();
        $sql = "SELECT * FROM restaurants";
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $restaurants = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $conn = null;
        
        return $response->withJson($restaurants, 200);
    } catch (PDOException $e) {
        return $response->withJson(['error' => 'Database error: ' . $e->getMessage()], 500);
    }
});

// Get a single restaurant
$app->get('/restaurants/{id}', function (Request $request, Response $response, array $args) use ($db) {
    try {
        $conn = $db->connect();
        $sql = "SELECT * FROM restaurants WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id', $args['id']);
        $stmt->execute();
        $restaurant = $stmt->fetch(PDO::FETCH_ASSOC);
        $conn = null;

        if ($restaurant) {
            $response->getBody()->write(json_encode($restaurant));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
        } else {
            $response->getBody()->write(json_encode(['error' => 'Restaurant not found']));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(404);
        }
    } catch (PDOException $e) {
        $error = ['error' => 'Database error: ' . $e->getMessage()];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

// Add a new restaurant
$app->post('/restaurants', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody();

    try {
        $conn = $db->connect();
        $sql = "INSERT INTO restaurants (name, address, contact) VALUES (:name, :address, :contact)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $data['name']);
        $stmt->bindParam(':address', $data['address']);
        $stmt->bindParam(':contact', $data['contact']);
        $stmt->execute();
        $restaurantId = $conn->lastInsertId();
        $conn = null;

        $response->getBody()->write(json_encode(['id' => $restaurantId, 'name' => $data['name'], 'address' => $data['address'], 'contact' => $data['contact']]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
    } catch (PDOException $e) {
        $error = ['error' => 'Database error: ' . $e->getMessage()];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

// Update a restaurant
$app->put('/restaurants/{id}', function (Request $request, Response $response, array $args) use ($db) {
    $data = $request->getParsedBody();

    try {
        $conn = $db->connect();
        $sql = "UPDATE restaurants SET name = :name, address = :address, contact = :contact WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $data['name']);
        $stmt->bindParam(':address', $data['address']);
        $stmt->bindParam(':contact', $data['contact']);
        $stmt->bindParam(':id', $args['id']);
        $stmt->execute();
        $conn = null;

        $response->getBody()->write(json_encode(['message' => 'Restaurant updated']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (PDOException $e) {
        $error = ['error' => 'Database error: ' . $e->getMessage()];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

// Delete a restaurant
$app->delete('/restaurants/{id}', function (Request $request, Response $response, array $args) use ($db) {
    try {
        $conn = $db->connect();
        $sql = "DELETE FROM restaurants WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id', $args['id']);
        $stmt->execute();
        $conn = null;

        $response->getBody()->write(json_encode(['message' => 'Restaurant deleted']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (PDOException $e) {
        $error = ['error' => 'Database error: ' . $e->getMessage()];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

$app->run();
