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

// Middleware for role checking
$roleMiddleware = function (string $requiredRole) {
    return function (Request $request, Response $response, callable $next) use ($requiredRole) {
        $authHeader = $request->getHeaderLine('Authorization');
        $user = json_decode(base64_decode(str_replace('Bearer ', '', $authHeader)), true);

        if (!isset($user['role']) || $user['role'] !== $requiredRole) {
            $response->getBody()->write(json_encode(['error' => 'Unauthorized']));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(403);
        }

        return $next($request, $response);
    };
};

// User Registration
$app->post('/users', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody();
    $name = filter_var($data['name'], FILTER_SANITIZE_STRING);
    $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
    $password = password_hash($data['password'], PASSWORD_DEFAULT);
    $role = isset($data['role']) && in_array($data['role'], ['admin', 'user']) ? $data['role'] : 'user';

    try {
        $conn = $db->connect();
        $sql = "INSERT INTO users (name, email, password, role) VALUES (:name, :email, :password, :role)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':role', $role);
        $stmt->execute();
        $userId = $conn->lastInsertId();
        $conn = null;

        $response->getBody()->write(json_encode(['id' => $userId, 'name' => $name, 'email' => $email, 'role' => $role]));
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
$app->get('/restaurants', function (Request $request, Response $response) use ($db) {
    try {
        $conn = $db->connect();
        $sql = "SELECT * FROM restaurants";
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $restaurants = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $conn = null;
        
        $response->getBody()->write(json_encode($restaurants));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (PDOException $e) {
        $error = ['error' => 'Database error: ' . $e->getMessage()];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
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
    
    // Log the received data
    error_log("Received data: " . json_encode($data));

    try {
        $conn = $db->connect();
        $sql = "INSERT INTO restaurants (name, address, contact, link) VALUES (:name, :address, :contact, :link)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $data['name']);
        $stmt->bindParam(':address', $data['address']);
        $stmt->bindParam(':contact', $data['contact']);
        $stmt->bindParam(':link', $data['link']);
        $stmt->execute();
        $restaurantId = $conn->lastInsertId();
        $conn = null;

        $response->getBody()->write(json_encode(['id' => $restaurantId, 'name' => $data['name'], 'address' => $data['address'], 'contact' => $data['contact'], 'link' => $data['link']]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
    } catch (PDOException $e) {
        error_log("Database error: " . $e->getMessage());  // Log database error
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
        $sql = "UPDATE restaurants SET name = :name, address = :address, contact = :contact, link = :link WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $data['name']);
        $stmt->bindParam(':address', $data['address']);
        $stmt->bindParam(':contact', $data['contact']);
        $stmt->bindParam(':link', $data['link']);
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
    $id = $args['id'];
    try {
        $conn = $db->connect();
        $sql = "DELETE FROM restaurants WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id', $id);
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

// Get Analytics Data
$app->get('/analytics', function (Request $request, Response $response) use ($db) {
    try {
        $conn = $db->connect();
        
        // Total Restaurants
        $sql = "SELECT COUNT(*) AS total FROM restaurants";
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $totalRestaurants = $stmt->fetchColumn();

        // Total Users
        $sql = "SELECT COUNT(*) AS total FROM users";
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $totalUsers = $stmt->fetchColumn();

        // Average Restaurant Age
        $sql = "SELECT AVG(DATEDIFF(NOW(), createdAt)) AS avgAge FROM restaurants";
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $averageRestaurantAge = $stmt->fetchColumn();

        // Average Time Since Last Login
        $sql = "SELECT AVG(DATEDIFF(NOW(), lastLogin)) AS avgLastLogin FROM users WHERE lastLogin IS NOT NULL";
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $averageLastLogin = $stmt->fetchColumn();

        $conn = null;

        $data = [
            'totalRestaurants' => (int) $totalRestaurants,
            'totalUsers' => (int) $totalUsers,
            'averageRestaurantAge' => round((float) $averageRestaurantAge, 2),
            'averageLastLogin' => round((float) $averageLastLogin, 2)
        ];

        $response->getBody()->write(json_encode($data));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (PDOException $e) {
        $error = ['error' => 'Database error: ' . $e->getMessage()];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

// Fetch reviews for a restaurant
$app->get('/reviews', function (Request $request, Response $response) use ($db) {
    $restaurantId = $request->getQueryParams()['restaurantId'] ?? null;

    if (!$restaurantId) {
        $response->getBody()->write(json_encode(['error' => 'restaurantId is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    try {
        $conn = $db->connect();
        $sql = "SELECT * FROM reviews WHERE restaurantId = :restaurantId";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':restaurantId', $restaurantId, PDO::PARAM_INT);
        $stmt->execute();
        $reviews = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $conn = null;

        $response->getBody()->write(json_encode($reviews));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(['error' => 'Database error: ' . $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

// Add a new review
$app->post('/reviews', function (Request $request, Response $response) use ($db) {
    $review = $request->getParsedBody();

    // Simplified required fields check
    if (!isset($review['restaurantId'], $review['title'], $review['comments'], $review['rating'], $review['name'], $review['date'])) {
        $response->getBody()->write(json_encode(['error' => 'All fields are required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    try {
        $conn = $db->connect();
        $sql = "INSERT INTO reviews (restaurantId, title, comments, rating, name, date) VALUES (:restaurantId, :title, :comments, :rating, :name, :date)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':restaurantId', $review['restaurantId'], PDO::PARAM_INT);
        $stmt->bindParam(':title', $review['title']);
        $stmt->bindParam(':comments', $review['comments']);
        $stmt->bindParam(':rating', $review['rating'], PDO::PARAM_INT);
        $stmt->bindParam(':name', $review['name']);
        $stmt->bindParam(':date', $review['date']);
        $stmt->execute();
        $review['id'] = $conn->lastInsertId();
        $conn = null;

        $response->getBody()->write(json_encode($review));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(['error' => 'Database error: ' . $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});




$app->run();
