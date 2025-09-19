<?php
/**
 * audit.php — WebShell Hunter (no auth)
 * Upload -> buka di browser -> scan -> lihat -> hapus
 *
 * ⚠️ Gunakan hati-hati. Selalu buat backup sebelum menghapus.
 * Setelah selesai, hapus file ini dari server.
 */

@ini_set('display_errors', 0);
@error_reporting(E_ALL & ~E_NOTICE);
@set_time_limit(0);

// ====== KONFIGURASI DASAR ======
define('BASE_PATH', __DIR__); // root pemindaian (default: folder file ini)
$EXCLUDE_DIRS = ['vendor','node_modules','.git','storage','logs','backup','php_quarantine'];
$SCAN_EXT = ['php','phtml','php5','php7','phar','inc'];  // ekstensi yang dipindai
$MAX_READ_BYTES = 300000; // baca sebagian file (300KB) untuk cepat
// ===============================

// Token sederhana untuk aksi POST
session_start();
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
function csrf(){ return $_SESSION['csrf'] ?? ''; }
function check_csrf($t){ return !empty($t) && hash_equals($_SESSION['csrf'] ?? '', $t); }

// Helper aman
function h($s){ return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function within_base($path){
  $base = realpath(BASE_PATH); $real = @realpath($path);
  if ($base===false || $real===false) return false;
  $base = rtrim($base, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
  $real = rtrim($real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
  return strpos($real, $base) === 0;
}

// Bangun daftar exclude absolut
$EXCLUDE_ABS = [];
foreach ($EXCLUDE_DIRS as $d) {
  $rp = @realpath(BASE_PATH . DIRECTORY_SEPARATOR . $d);
  if ($rp) $EXCLUDE_ABS[] = $rp;
}

// ================== DETEKSI POLA ==================
/**
 * Kembalikan array alasan kecurigaan.
 * Tidak semua alasan = pasti malware. Ini indikator untuk review.
 */
function analyze_file($path, $maxBytes){
  $reasons = [];
  $size = @filesize($path);
  if ($size === false) return $reasons;

  // Baca sebagian awal & akhir (agar tangkap obfuscation di bawah)
  $head = @file_get_contents($path, false, null, 0, min($size, $maxBytes));
  if ($head === false) $head = '';

  // Tambahan: baca tail 64KB
  $tail = '';
  if ($size > 65536) {
    $tail = @file_get_contents($path, false, null, max(0, $size-65536), 65536) ?: '';
  }
  $blob = $head . "\n" . $tail;

  // Pola fungsi berbahaya/sering dipakai shell
  $patterns = [
    'eval'              => '/\beval\s*\(/i',
    'assert'            => '/\bassert\s*\(/i',
    'create_function'   => '/\bcreate_function\s*\(/i',
    'preg_replace_e'    => '/preg_replace\s*\(\s*["\'].*?\/e.*?["\']/i',
    'base64_decode'     => '/\bbase64_decode\s*\(/i',
    'gzinflate'         => '/\bgzinflate\s*\(/i',
    'gzuncompress'      => '/\bgzuncompress\s*\(/i',
    'str_rot13'         => '/\bstr_rot13\s*\(/i',
    'hex2bin'           => '/\bhex2bin\s*\(/i',
    'pack'              => '/\bpack\s*\(\s*["\']H/i',
    'system'            => '/\bsystem\s*\(/i',
    'passthru'          => '/\bpassthru\s*\(/i',
    'shell_exec'        => '/\bshell_exec\s*\(/i',
    'exec'              => '/\bexec\s*\(/i',
    'popen'             => '/\bpopen\s*\(/i',
    'proc_open'         => '/\bproc_open\s*\(/i',
    'curl_exec'         => '/\bcurl_exec\s*\(/i',
    'fsockopen'         => '/\bfsockopen\s*\(/i',
    'file_get_contents' => '/\bfile_get_contents\s*\(\s*[\'"]\s*(?:https?:\/\/|php:\/\/input)/i',
    'move_uploaded_file'=> '/\bmove_uploaded_file\s*\(/i',
    'set_time_limit'    => '/\bset_time_limit\s*\(/i',
    'chmod777'          => '/\bchmod\s*\(\s*.*?\b0?77[0-7]\b/i',
  ];

  foreach ($patterns as $label=>$regex){
    if (preg_match($regex, $blob)) $reasons[] = $label;
  }

  // Nama/brand shell populer
  $shellMarks = [
    'WSO'        => '/\bWSO\s*Shell\b/i',
    'b374k'      => '/\bb374k\b/i',
    'r57'        => '/\br57shell\b/i',
    'c99'        => '/\bc99shell\b/i',
    'FilesMan'   => '/\bFilesMan\b/i',
    'Owl'        => '/\bOwl\W*Shell\b/i',
    'tinyfilemanager.github.io' => '/tinyfilemanager\.github\.io/i',
    'filemanager' => '/\bFile\s*Manager\b/i',
    'uploader'    => '/\buploader\b/i',
  ];
  foreach ($shellMarks as $label=>$regex){
    if (preg_match($regex, $blob)) $reasons[] = $label;
  }

  // PHP disamarkan dalam gambar/berkas lain (GIF89a lalu <?php)
  if (preg_match('/GIF8?9a.*<\?php/s', $blob)) $reasons[] = 'gif_php';

  // Obfuscation umum (var panjang, concat tidak wajar)
  if (preg_match('/\$\w{12,}\s*=\s*[\'"][A-Za-z0-9+\/=]{60,}[\'"]\s*;/', $blob)) $reasons[] = 'long_base64';
  if (preg_match('/\$\w{12,}\s*=\s*["\'][^"\']{200,}["\']\s*;/', $blob)) $reasons[] = 'long_string';

  // Tanda remote include
  if (preg_match('/include|require/i', $blob) && preg_match('/https?:\/\//i', $blob)) $reasons[] = 'remote_include';

  // Unlink massal
  if (preg_match('/\bunlink\s*\(/i', $blob)) $reasons[] = 'unlink';

  // Unik: jika file bernama mencurigakan
  $bn = basename($path);
  if (preg_match('/^(up|load|shell|ws|r57|c99|wso|fm|manager|ajax|api|cache|tmp)[\w\-]*\.(php|phtml|php5)$/i', $bn)) {
    $reasons[] = 'suspicious_name';
  }

  // Hilangkan duplikat
  $reasons = array_values(array_unique($reasons));
  return $reasons;
}

// ================== SCAN FOLDER ==================
function scan_all($base, $excludeAbs, $exts, $maxBytes){
  $out = [];
  $baseReal = realpath($base);
  if ($baseReal===false) return $out;

  $iter = new RecursiveIteratorIterator(
    new RecursiveCallbackFilterIterator(
      new RecursiveDirectoryIterator($baseReal, FilesystemIterator::SKIP_DOTS),
      function($current) use ($excludeAbs){
        $p = $current->getPathname();
        foreach ($excludeAbs as $ex) {
          if ($ex && strpos($p, $ex) === 0) return false;
        }
        return true;
      }
    ),
    RecursiveIteratorIterator::LEAVES_ONLY
  );

  foreach ($iter as $f) {
    if (!$f->isFile()) continue;
    $ext = strtolower($f->getExtension());
    if (!in_array($ext, $exts, true)) continue;
    $path = $f->getPathname();
    if (!within_base($path)) continue;

    $reasons = analyze_file($path, $maxBytes);
    if (!empty($reasons)) {
      $out[] = [
        'path'    => $path,
        'rel'     => ltrim(substr($path, strlen($baseReal)), DIRECTORY_SEPARATOR),
        'size'    => $f->getSize(),
        'mtime'   => $f->getMTime(),
        'reasons' => $reasons,
        'score'   => count($reasons), // sederhana: banyak alasan = lebih mencurigakan
      ];
    }
  }

  // urutkan by score desc lalu nama
  usort($out, function($a,$b){
    if ($a['score'] === $b['score']) return strcmp($a['rel'],$b['rel']);
    return $b['score'] <=> $a['score'];
  });
  return $out;
}

// ================== ACTION: DELETE / VIEW ==================
$messages = []; $errors = [];
$self = strtok($_SERVER['REQUEST_URI'],'?');

// Hapus file (POST)
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['do_delete'])) {
  if (!check_csrf($_POST['csrf'] ?? '')) {
    $errors[] = "CSRF token tidak valid.";
  } else {
    $target = $_POST['file'] ?? '';
    $confirm = trim($_POST['confirm'] ?? '');
    if ($confirm !== 'DELETE') {
      $errors[] = "Ketik 'DELETE' pada kolom konfirmasi untuk menghapus.";
    } elseif (!$target) {
      $errors[] = "File tidak diberikan.";
    } else {
      $target = str_replace("\0",'',$target);
      if (!within_base($target)) {
        $errors[] = "Path di luar BASE_PATH.";
      } elseif (!is_file($target)) {
        $errors[] = "File tidak ditemukan.";
      } elseif (realpath($target) === realpath(__FILE__)) {
        $errors[] = "Diblok: tidak boleh menghapus script ini.";
      } else {
        if (@unlink($target)) {
          $messages[] = "Berhasil menghapus: " . h($target);
        } else {
          $errors[] = "Gagal menghapus: " . h($target);
        }
      }
    }
  }
}

// View file (GET ?view=base64)
$viewFile = null; $viewCode = null;
if (isset($_GET['view'])) {
  $decoded = base64_decode($_GET['view'], true);
  if ($decoded && within_base($decoded) && is_file($decoded)) {
    $viewFile = $decoded;
    $raw = @file_get_contents($decoded, false, null, 0, 200000);
    if ($raw === false) $raw = '';
    $viewCode = htmlspecialchars($raw, ENT_QUOTES, 'UTF-8');
  } else {
    $errors[] = "Tidak bisa membuka file untuk preview.";
  }
}

// Jalankan scan
$rows = scan_all(BASE_PATH, $EXCLUDE_ABS, $SCAN_EXT, $MAX_READ_BYTES);

// ========= RENDER =========
?>
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>WebShell Hunter — <?=h(BASE_PATH)?></title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<style>
:root{--bg:#f8fafc;--text:#111;--muted:#6b7280;--bd:#e5e7eb;--ok:#10b981;--warn:#f59e0b;--danger:#ef4444;--primary:#2563eb}
*{box-sizing:border-box}body{margin:20px;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial}
h1{font-size:20px;margin:0 0 10px} .small{color:var(--muted);font-size:12px}
.card{background:#fff;border:1px solid var(--bd);border-radius:10px;padding:12px}
.badge{display:inline-block;border-radius:999px;padding:3px 8px;font-size:11px;border:1px solid #eee;background:#f9fafb;margin:1px}
.badge.danger{background:#fee2e2;border-color:#fecaca;color:#991b1b}
.badge.warn{background:#fff7d6;border-color:#fde68a;color:#92400e}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{padding:10px;border-bottom:1px solid var(--bd);vertical-align:top;font-size:14px}
th{background:#f3f4f6;text-align:left}
.actions{display:flex;gap:6px}
.btn{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid var(--bd);border-radius:8px;background:#fff;cursor:pointer;font-size:13px;text-decoration:none}
.btn:hover{border-color:#cbd5e1}
.btn.view{color:#1d4ed8}
.btn.del{background:#fee2e2;border-color:#fecaca;color:#991b1b}
.code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#0b1020;color:#e5e7eb;padding:10px;border-radius:8px;overflow:auto;max-height:55vh}
.kv{display:flex;gap:10px;flex-wrap:wrap}
.kv > div{background:#f9fafb;border:1px solid var(--bd);padding:6px 8px;border-radius:8px;font-size:12px}
footer{margin-top:18px;color:var(--muted);font-size:12px}
.icon{width:14px;height:14px;display:inline-block}
</style>
</head>
<body>
<h1>WebShell Hunter</h1>
<div class="small">Base: <b><?=h(realpath(BASE_PATH))?></b> — Ditemukan <b><?=count($rows)?></b> file mencurigakan. Hapus file ini (audit.php) setelah selesai.</div>

<?php if ($errors): ?>
  <div class="card" style="border-color:#fecaca;background:#fff1f2;margin-top:10px">
    <b>Errors</b><ul><?php foreach($errors as $e) echo "<li>".h($e)."</li>"; ?></ul>
  </div>
<?php endif; ?>

<?php if ($messages): ?>
  <div class="card" style="border-color:#bbf7d0;background:#ecfdf5;margin-top:10px">
    <b>Info</b><ul><?php foreach($messages as $m) echo "<li>$m</li>"; ?></ul>
  </div>
<?php endif; ?>

<?php if ($viewFile): ?>
  <div class="card" style="margin-top:10px">
    <div class="kv">
      <div><b>Preview:</b> <?=h($viewFile)?></div>
      <div>Ukuran: <?=number_format(@filesize($viewFile))?> B</div>
      <div>Mod: <?=date('Y-m-d H:i:s', @filemtime($viewFile))?></div>
    </div>
    <pre class="code"><?= $viewCode ?></pre>
  </div>
<?php endif; ?>

<div class="card" style="margin-top:10px">
  <table>
    <thead>
      <tr>
        <th style="width:42%">Path</th>
        <th>Reason</th>
        <th style="width:160px">Action</th>
      </tr>
    </thead>
    <tbody>
    <?php if (!count($rows)): ?>
      <tr><td colspan="3">Tidak ada kandidat mencurigakan.</td></tr>
    <?php else: foreach($rows as $r): 
      $viewParam = base64_encode($r['path']);
      $badges = [];
      foreach ($r['reasons'] as $reason) {
        // tandai high-risk
        $cls = in_array($reason, ['eval','assert','shell_exec','exec','system','passthru','proc_open','popen','preg_replace_e','FilesMan','b374k','r57','c99']) ? 'danger' :
               (in_array($reason, ['file_get_contents','move_uploaded_file','set_time_limit','unlink','remote_include','filemanager','tinyfilemanager.github.io','uploader']) ? 'warn' : '');
        $badges[] = "<span class='badge $cls'>".h($reason)."</span>";
      }
    ?>
      <tr>
        <td>
          <div><code><?=h($r['rel'])?></code></div>
          <div class="small"><?=number_format($r['size'])?> B · <?=date('Y-m-d H:i:s', $r['mtime'])?></div>
        </td>
        <td><?=implode(' ', $badges)?></td>
        <td>
          <div class="actions">
            <a class="btn view" href="?view=<?=urlencode($viewParam)?>">️ Lihat</a>
            <form method="post" onsubmit="return confirmDelete(this)" style="display:inline">
              <input type="hidden" name="csrf" value="<?=h(csrf())?>">
              <input type="hidden" name="file" value="<?=h($r['path'])?>">
              <input type="hidden" name="do_delete" value="1">
              <input type="text" name="confirm" placeholder="ketik DELETE" style="width:90px;font-size:12px">
              <button class="btn del" type="submit">🗑️ Hapus</button>
            </form>
          </div>
        </td>
      </tr>
    <?php endforeach; endif; ?>
    </tbody>
  </table>
</div>

<footer>
  <div>Indikator umum: <span class="badge danger">eval</span><span class="badge danger">shell_exec</span><span class="badge warn">file_get_contents(http)</span><span class="badge warn">uploader</span> dll. Tidak semua indikator = malware, tapi layak diaudit.</div>
</footer>

<script>
function confirmDelete(form){
  const v = form.querySelector('input[name="confirm"]').value.trim();
  if(v !== 'DELETE'){
    alert("Ketik DELETE pada kolom konfirmasi untuk menghapus.");
    return false;
  }
  return confirm("Yakin hapus file ini? Tindakan tidak bisa dibatalkan.");
}
</script>
</body>
</html>
