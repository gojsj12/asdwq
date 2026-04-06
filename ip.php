<?php
date_default_timezone_set('Asia/Bangkok');

// ================== [ START TIMER ] ==================
$start_time = microtime(true);

// 1. ฟังก์ชันดึง IP แบบกรอง Proxy หลายชั้น (แต่ยังปลอดภัย)
function getHardcoreIP() {
    $ip = $_SERVER['REMOTE_ADDR'];
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ipList[0]);
    }
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : $_SERVER['REMOTE_ADDR'];
}

// ================== [ DEVICE / OS ] ==================
function getOS($ua) {
    if (preg_match('/windows/i', $ua)) return 'Windows';
    if (preg_match('/linux/i', $ua)) return 'Linux';
    if (preg_match('/mac/i', $ua)) return 'Mac';
    if (preg_match('/android/i', $ua)) return 'Android';
    if (preg_match('/iphone/i', $ua)) return 'iPhone';
    return 'Unknown';
}

function getDevice($ua) {
    if (preg_match('/mobile/i', $ua)) return 'Mobile';
    if (preg_match('/tablet/i', $ua)) return 'Tablet';
    return 'Desktop';
}

// 2. เก็บข้อมูลเดิม
$datetime      = date('Y-m-d H:i:s');
$ipaddress     = getHardcoreIP();
$browser       = substr($_SERVER['HTTP_USER_AGENT'] ?? 'N/A', 0, 255);
$referer       = substr($_SERVER['HTTP_REFERER'] ?? 'Direct', 0, 255);
$current_page  = substr($_SERVER['REQUEST_URI'] ?? 'N/A', 0, 255);

$method        = $_SERVER['REQUEST_METHOD'] ?? 'N/A';
$language      = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'N/A', 0, 50);

// ================== [ NEW DATA ] ==================
$os = getOS($browser);
$device = getDevice($browser);
$is_bot = preg_match('/bot|crawl|spider|curl|python/i', $browser) ? 1 : 0;
$query_string = $_SERVER['QUERY_STRING'] ?? '';
$content_length = $_SERVER['CONTENT_LENGTH'] ?? 0;
$country = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? 'Unknown';

// header ทั้งหมด
$headers = function_exists('getallheaders') ? getallheaders() : [];
$header_json = json_encode($headers);

// ================== [ BASIC DETECT ] ==================
$suspicious = 0;
if (preg_match('/(union|select|insert|update|delete|drop|\'|"|<script>|<\/script>)/i', $current_page)) {
    $suspicious = 1;
}

// ================== [ HARDCORE UPGRADE SYSTEM ] ==================
$payload = json_encode([$_GET, $_POST, $_COOKIE, $_REQUEST]);

$score = 0;
if (preg_match('/(union.*select|select.*from|sleep\(|benchmark\()/i', $payload)) $score += 5;
if (preg_match('/(<script|onerror=|onload=)/i', $payload)) $score += 5;
if (strpos($current_page, '../') !== false) $score += 5;
if ($method === 'POST' && empty($_POST)) $score += 2;
if (strlen($payload) > 5000) $score += 2;
if ($is_bot) $score += 2;

if ($score >= 5) $suspicious = 1;

// ================== [ IP MEMORY ] ==================
if (!is_dir('ip_history')) mkdir('ip_history');

$ip_file = 'ip_history/' . md5($ipaddress) . '.json';

$data = ['count'=>1,'last'=>time(),'suspicious'=>$suspicious];

if (file_exists($ip_file)) {
    $old = json_decode(file_get_contents($ip_file), true);
    $data['count'] = $old['count'] + 1;
    $data['suspicious'] = $old['suspicious'] + $suspicious;
}

file_put_contents($ip_file, json_encode($data));

// ================== [ RATE LIMIT + BLOCK ] ==================
if ($data['count'] > 300) $suspicious = 1;

if ($data['suspicious'] > 5 || $data['count'] > 500) {
    file_put_contents('blocked_ips.txt', $ipaddress . PHP_EOL, FILE_APPEND);
}

if (file_exists('blocked_ips.txt')) {
    $blocked = file('blocked_ips.txt', FILE_IGNORE_NEW_LINES);
    if (in_array($ipaddress, $blocked)) {
        http_response_code(403);
        die("Forbidden");
    }
}

// ================== [ RESPONSE TIME ] ==================
$end_time = microtime(true);
$response_time = round(($end_time - $start_time), 5);

// ================== [ LOG SYSTEM เดิม ] ==================
$file = 'log_hardcore_' . date('Y-m') . '.csv';
$file_exists = file_exists($file);

$fp = fopen($file, 'a');

if ($fp) {
    if (flock($fp, LOCK_EX)) {
        if (!$file_exists) {
            fwrite($fp, "\xEF\xBB\xBF");
            fputcsv($fp, [
                'Date Time','IP','Method','URL','Suspicious',
                'Referer','Lang','UserAgent',
                'OS','Device','Bot','Country',
                'Query','Length','ResponseTime'
            ]);
        }

        fputcsv($fp, [
            $datetime,$ipaddress,$method,$current_page,$suspicious,
            $referer,$language,$browser,
            $os,$device,$is_bot,$country,
            $query_string,$content_length,$response_time
        ]);

        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
}

// ================== [ DEEP LOG ] ==================
$port = $_SERVER['REMOTE_PORT'] ?? 'N/A';
$protocol = $_SERVER['SERVER_PROTOCOL'] ?? 'N/A';

$deep_file = 'log_deep_' . date('Y-m') . '.csv';
$deep_exists = file_exists($deep_file);

$fp2 = fopen($deep_file, 'a');

if ($fp2) {
    if (flock($fp2, LOCK_EX)) {

        if (!$deep_exists) {
            fwrite($fp2, "\xEF\xBB\xBF");
            fputcsv($fp2, [
                'Date','IP','Score','Count','SuspiciousTotal',
                'Port','Protocol','Headers'
            ]);
        }

        fputcsv($fp2, [
            $datetime,
            $ipaddress,
            $score,
            $data['count'],
            $data['suspicious'],
            $port,
            $protocol,
            $header_json
        ]);

        fflush($fp2);
        flock($fp2, LOCK_UN);
    }
    fclose($fp2);
}
?>