<?php
// Control de rate limiting per IP contra atacs de força bruta.
//
// Un atacant que vulgui endevinar 3 paraules ha de preguntar al servidor si existeix
// l'identificador que en deriva. Cada resposta "no existeix" (GET/DELETE 404) o
// "ja existeix" en crear (POST 409) compta com a intent fallit. Superat el límit,
// la IP queda bloquejada i el bloqueig es duplica a cada reincidència.
// Els encerts no reinicien el comptador: si no, un atacant amb una combinació vàlida
// podria intercalar-la per esquivar el límit.

const RL_MAX_FAILS      = 5;      // intents fallits permesos...
const RL_FAIL_WINDOW    = 900;    // ...en 15 minuts
const RL_LOCK_BASE      = 900;    // primer bloqueig: 15 minuts
const RL_LOCK_MAX       = 86400;  // bloqueig màxim: 24 hores
const RL_MAX_CREATES    = 10;     // codis nous...
const RL_CREATE_WINDOW  = 3600;   // ...per hora
const RL_MAX_REQUESTS   = 60;     // peticions totals...
const RL_REQUEST_WINDOW = 60;     // ...per minut

final class RateLimit
{
    private $fh;
    private array $s;
    private int $now;

    public function __construct(string $dir)
    {
        if (!is_dir($dir)) mkdir($dir, 0700, true);
        if (mt_rand(1, 100) === 1) self::cleanup($dir);

        $this->now = time();
        $this->fh = fopen("$dir/" . hash('sha256', self::clientKey()) . '.json', 'c+');
        // Bloqueig exclusiu durant tota la petició: les peticions d'una mateixa IP
        // es serialitzen i no es poden saltar el límit fent-les en paral·lel.
        flock($this->fh, LOCK_EX);
        $data = json_decode(stream_get_contents($this->fh), true);
        $this->s = (is_array($data) ? $data : []) + ['fails' => [], 'creates' => [], 'requests' => [], 'locks' => 0, 'lockedUntil' => 0];

        $this->s['fails']    = $this->recent($this->s['fails'], RL_FAIL_WINDOW);
        $this->s['creates']  = $this->recent($this->s['creates'], RL_CREATE_WINDOW);
        $this->s['requests'] = $this->recent($this->s['requests'], RL_REQUEST_WINDOW);
        // Un dia sencer sense bloquejos i el càstig torna a començar de zero.
        if ($this->s['lockedUntil'] + RL_LOCK_MAX < $this->now) $this->s['locks'] = 0;
    }

    public function __destruct()
    {
        $this->save();
        flock($this->fh, LOCK_UN);
        fclose($this->fh);
    }

    // IPv4 tal qual; IPv6 agrupada per /64, ja que un client sol disposar de tot el prefix.
    // Només es fa servir REMOTE_ADDR: capçaleres com X-Forwarded-For les pot falsificar el client.
    private static function clientKey(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $bin = @inet_pton($ip);
        if ($bin !== false && strlen($bin) === 16) return bin2hex(substr($bin, 0, 8)) . '::/64';
        return $ip;
    }

    // Comprova si es pot atendre la petició; si no, respon 429 i acaba.
    public function check(bool $isCreate = false): void
    {
        if ($this->s['lockedUntil'] > $this->now) {
            $this->deny($this->s['lockedUntil'] - $this->now, 'Massa intents fallits');
        }
        if (count($this->s['requests']) >= RL_MAX_REQUESTS) {
            $this->deny($this->s['requests'][0] + RL_REQUEST_WINDOW - $this->now, 'Massa peticions');
        }
        if ($isCreate && count($this->s['creates']) >= RL_MAX_CREATES) {
            $this->deny($this->s['creates'][0] + RL_CREATE_WINDOW - $this->now, 'Massa codis creats');
        }
        $this->s['requests'][] = $this->now;
        if ($isCreate) $this->s['creates'][] = $this->now;
    }

    public function fail(): void
    {
        $this->s['fails'][] = $this->now;
        if (count($this->s['fails']) >= RL_MAX_FAILS) {
            $this->s['locks']++;
            $this->s['lockedUntil'] = $this->now + min(RL_LOCK_BASE * 2 ** ($this->s['locks'] - 1), RL_LOCK_MAX);
            $this->s['fails'] = [];
        }
    }

    private function deny(int $retryAfter, string $reason): never
    {
        $retryAfter = max(1, $retryAfter);
        header("Retry-After: $retryAfter");
        http_response_code(429);
        echo json_encode(['error' => $reason, 'retryAfter' => $retryAfter]);
        exit; // el destructor desa l'estat i allibera el fitxer
    }

    private function recent(array $times, int $window): array
    {
        return array_values(array_filter($times, fn($t) => $t > $this->now - $window));
    }

    private function save(): void
    {
        ftruncate($this->fh, 0);
        rewind($this->fh);
        fwrite($this->fh, json_encode($this->s));
        fflush($this->fh);
    }

    // Esborra l'estat d'IPs inactives des de fa més de 2 dies.
    private static function cleanup(string $dir): void
    {
        foreach (glob("$dir/*.json") as $f) {
            if (filemtime($f) < time() - 2 * RL_LOCK_MAX) @unlink($f);
        }
    }
}
