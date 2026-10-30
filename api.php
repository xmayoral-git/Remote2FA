<?php
// Emmagatzematge mínim de blobs xifrats. El servidor no pot llegir-ne el contingut:
// el xifratge i desxifratge es fan al navegador (vault.js).
// Cada identificador (derivat de 3 paraules) conté un sol codi i no es pot sobreescriure.
require __DIR__ . '/ratelimit.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$dir = __DIR__ . '/data';
$method = $_SERVER['REQUEST_METHOD'];

$limit = new RateLimit("$dir/ratelimit");
$limit->check($method === 'POST');

$id = $_GET['id'] ?? '';
if (!preg_match('/^[0-9a-f]{64}$/', $id)) {
    http_response_code(400);
    exit('{"error":"id invàlid"}');
}

$file = "$dir/$id.json";

switch ($method) {
    case 'GET':
        if (!is_file($file)) {
            $limit->fail();
            http_response_code(404);
            exit('{"error":"no existeix"}');
        }
        readfile($file);
        break;

    case 'POST':
        $body = file_get_contents('php://input', false, null, 0, 65536);
        $blob = json_decode($body, true);
        if (!is_array($blob) || !isset($blob['iv'], $blob['ct']) || !is_string($blob['iv']) || !is_string($blob['ct'])) {
            http_response_code(400);
            exit('{"error":"format invàlid"}');
        }
        // Mode 'x': només crea; falla si ja existeix (també amb peticions simultànies).
        $fh = @fopen($file, 'x');
        if ($fh === false) {
            if (is_file($file)) {
                // Saber que una combinació existeix ja és informació per a un atacant.
                $limit->fail();
                http_response_code(409);
                exit('{"error":"ja existeix"}');
            }
            http_response_code(500);
            exit('{"error":"no s\'ha pogut escriure"}');
        }
        fwrite($fh, json_encode(['v' => 1, 'iv' => $blob['iv'], 'ct' => $blob['ct'], 'created' => time()]));
        fclose($fh);
        http_response_code(201);
        echo '{"ok":true}';
        break;

    case 'DELETE':
        if (!is_file($file)) {
            $limit->fail();
            http_response_code(404);
            exit('{"error":"no existeix"}');
        }
        unlink($file);
        echo '{"ok":true}';
        break;

    default:
        http_response_code(405);
        echo '{"error":"mètode no permès"}';
}
