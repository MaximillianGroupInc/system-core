<?php
declare(strict_types=1);

function assertSameValue(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(
            $message . "\nExpected: " . var_export($expected, true) . "\nActual:   " . var_export($actual, true)
        );
    }
}

function assertArrayHasKeyValue(array $array, string $key, mixed $expected, string $message): void
{
    if (!array_key_exists($key, $array)) {
        throw new RuntimeException($message . "\nMissing key: " . $key);
    }

    assertSameValue($expected, $array[$key], $message);
}

$registeredFilters = [];
function add_filter(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void
{
    global $registeredFilters;
    $registeredFilters[$hook][] = $callback;
}

define('ABSPATH', __DIR__);
require __DIR__ . '/../var/www/html/wp-content/mu-plugins/spx-upload-mimes.php';

if (!isset($registeredFilters['upload_mimes'][0], $registeredFilters['wp_check_filetype_and_ext'][0])) {
    throw new RuntimeException('Expected plugin filters were not registered.');
}

$uploadMimesFilter = $registeredFilters['upload_mimes'][0];
$filetypeFilter = $registeredFilters['wp_check_filetype_and_ext'][0];

$tmpDir = sys_get_temp_dir() . '/spx-upload-mimes-tests-' . bin2hex(random_bytes(4));
if (!mkdir($tmpDir) && !is_dir($tmpDir)) {
    throw new RuntimeException('Failed to create temporary test directory.');
}

try {
    $updatedMimes = $uploadMimesFilter([
        'jpg' => 'image/jpeg',
        'wav' => 'application/octet-stream',
    ]);

    assertArrayHasKeyValue($updatedMimes, 'jpg', 'image/jpeg', 'Existing MIME mapping should be retained.');
    assertArrayHasKeyValue($updatedMimes, 'ico', 'image/x-icon', 'ICO MIME mapping should be added.');
    assertArrayHasKeyValue($updatedMimes, 'wav', 'audio/wav', 'WAV MIME mapping should be canonicalized.');
    assertArrayHasKeyValue($updatedMimes, 'mp3', 'audio/mpeg', 'MP3 MIME mapping should be canonicalized.');

    $initialData = ['ext' => '', 'type' => '', 'proper_filename' => false];
    $ignored = $filetypeFilter($initialData, $tmpDir . '/ignored.txt', 'ignored.txt', []);
    assertSameValue($initialData, $ignored, 'Non-managed extensions should be ignored.');

    $alreadyResolved = ['ext' => 'wav', 'type' => 'audio/wav', 'proper_filename' => false];
    $resolved = $filetypeFilter($alreadyResolved, $tmpDir . '/resolved.wav', 'resolved.wav', []);
    assertSameValue($alreadyResolved, $resolved, 'Resolved checks should not be modified.');

    $fakeMp3Path = $tmpDir . '/fake.mp3';
    file_put_contents($fakeMp3Path, 'not an mp3 payload');
    $fakeMp3 = $filetypeFilter($initialData, $fakeMp3Path, 'fake.mp3', []);
    assertSameValue($initialData, $fakeMp3, 'Spoofed content should remain rejected.');

    $wavPath = $tmpDir . '/sample.wav';
    file_put_contents(
        $wavPath,
        "RIFF\x24\x80\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x80\x00\x00"
    );
    $wavDetected = $filetypeFilter($initialData, $wavPath, 'sample.WAV', []);
    assertArrayHasKeyValue($wavDetected, 'ext', 'wav', 'WAV extension should be normalized to lowercase.');
    assertArrayHasKeyValue($wavDetected, 'type', 'audio/wav', 'Valid WAV content should be accepted.');

    $icoPath = $tmpDir . '/favicon.ico';
    file_put_contents(
        $icoPath,
        "\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x18\x00\x30\x00\x00\x00\x16\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00"
    );
    $icoDetected = $filetypeFilter($initialData, $icoPath, 'favicon.ico', []);
    assertArrayHasKeyValue($icoDetected, 'ext', 'ico', 'Valid ICO content should set extension.');
    assertArrayHasKeyValue($icoDetected, 'type', 'image/x-icon', 'Valid ICO content should use canonical MIME.');

    $missingFile = $filetypeFilter($initialData, $tmpDir . '/missing.wav', 'missing.wav', []);
    assertSameValue($initialData, $missingFile, 'Unreadable files should remain rejected.');

    echo "All tests passed.\n";
} finally {
    if (is_dir($tmpDir)) {
        $entries = scandir($tmpDir);
        if (is_array($entries)) {
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                @unlink($tmpDir . '/' . $entry);
            }
        }
        @rmdir($tmpDir);
    }
}
