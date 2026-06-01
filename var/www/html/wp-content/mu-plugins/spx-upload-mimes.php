<?php
declare(strict_types=1);

/**
 * Plugin Name: SPX Upload MIME Types
 * Description: Extends the WordPress Media Library allowlist for a managed
 *              set of audio, image, video, and vCard file types. Installed as
 *              a must-use plugin so it stays active regardless of plugins.
 *
 * Background
 * ----------
 * WordPress deliberately omits ICO from its default upload_mimes list (legacy
 * IE security policy) and relies on PHP's fileinfo/libmagic extension to
 * verify that the detected MIME type matches the declared extension.  On
 * Ubuntu 22/24 with PHP 8.2/8.3, libmagic frequently returns:
 *
 *   • WAV  → audio/x-wav  (WordPress expects audio/wav)
 *   • MP3  → audio/x-mpeg (WordPress expects audio/mpeg)
 *   • ICO  → not in default allowlist at all
 *   * WEBA, M4A, AAC, FLAC, VCF, MPEG, MP4 - as well.
 *
 * Both hooks below are required:
 *   1. upload_mimes              – adds ICO to the extension → MIME map so
 *                                  WordPress does not reject it before even
 *                                  reaching the fileinfo check.
 *   2. wp_check_filetype_and_ext – overrides the fileinfo verdict for these
 *                                  managed extensions so that a MIME mismatch
 *                                  between libmagic and the WordPress map
 *                                  does not veto the upload.
 *
 * Standard WordPress Media Library uploads (via /wp-admin/async-upload.php
 * or /wp-json/wp/v2/media) are used for these file types.  The TUS resumable
 * upload endpoint (/files/) is reserved exclusively for Submission Core audio
 * ingestion and must NOT be used for Media Library uploads.
 */

\defined( 'ABSPATH' ) || exit;

/**
 * Canonical extension → MIME map for the managed file types this plugin unlocks.
 *
 * Single source of truth used by both the upload_mimes allowlist filter and
 * the wp_check_filetype_and_ext fileinfo-override filter below.
 *
 * @var array<string, string>
 */
const SPX_EXTRA_MIMES = [
    'ico'  => 'image/x-icon',
    'wav'  => 'audio/wav',
    'mp3'  => 'audio/mpeg',
    'weba' => 'audio/webm',
    'webp' => 'image/webp',
    'flac' => 'audio/flac',
    'aac'  => 'audio/aac',
    'm4a'  => 'audio/mp4',
    'ogg'  => 'audio/ogg',
    'mpeg' => 'video/mpeg',
    'mp4'  => 'video/mp4',
    'vcf' => 'text/vcard',
];

/**
 * MIME strings that PHP's finfo/libmagic may legitimately return for genuine
 * files of each extension.  The override in wp_check_filetype_and_ext is only
 * applied when the detected MIME is one of these known-good variants, ensuring
 * that a non-audio/non-ICO file renamed to one of these extensions is still
 * rejected by WordPress's file-content validation.
 *
 * @var array<string, list<string>>
 */
const SPX_FINFO_VARIANTS = [
    'ico'  => [ 'image/vnd.microsoft.icon', 'image/x-icon' ],
    'wav'  => [ 'audio/x-wav', 'audio/wav' ],
    'mp3'  => [ 'audio/x-mpeg', 'audio/mpeg', 'audio/mp3' ],
    'weba' => [ 'audio/webm', 'video/webm' ],
    'webp' => [ 'image/webp' ],
    'flac' => [ 'audio/flac', 'audio/x-flac' ],
    'aac'  => [ 'audio/aac', 'audio/x-aac' ],
    'm4a'  => [ 'audio/mp4', 'audio/x-m4a' ],
    'ogg'  => [ 'audio/ogg', 'application/ogg' ],
    'mpeg' => [ 'video/mpeg', 'audio/mpeg' ],
    'mp4'  => [ 'video/mp4', 'application/mp4' ],
    'vcf' => [ 'text/vcard', 'text/x-vcard' ],
];

/**
 * Add all managed extensions to the allowed upload MIME types.
 * Some are already in WordPress defaults; the full map is applied here to keep
 * extension-to-MIME values explicit and consistent.
 *
 * @param array $mimes Existing extension => MIME map.
 * @return array
 */
add_filter( 'upload_mimes', static function ( array $mimes ): array {
    foreach ( SPX_EXTRA_MIMES as $ext => $mime ) {
        $mimes[ $ext ] = $mime;
    }
    return $mimes;
} );

/**
 * Override fileinfo/libmagic MIME detection for the managed extensions.
 *
 * PHP's fileinfo extension (libmagic) returns non-canonical MIME strings for
 * these formats on Ubuntu 22/24 with PHP 8.2/8.3:
 *   WAV → audio/x-wav  instead of audio/wav
 *   MP3 → audio/x-mpeg instead of audio/mpeg
 *
 * WordPress's wp_check_filetype_and_ext() compares the detected MIME against
 * the upload_mimes map and blocks the upload if they differ.  This filter
 * supplies the canonical MIME string when:
 *   a) the extension is one of the managed types, AND
 *   b) the default check did not already resolve the type cleanly, AND
 *   c) finfo independently confirms the file contents are a genuine instance
 *      of that type (i.e. the detected MIME is in SPX_FINFO_VARIANTS).
 *
 * Condition (c) prevents a file with unrelated contents that has simply been
 * renamed to .ico/.wav/.mp3 from bypassing WordPress's file-content
 * validation — only known libmagic variants for each format are accepted.
 *
 * @param array       $data     {ext, type, proper_filename} from the default check.
 * @param string      $file     Full path to the temporary upload file.
 * @param string      $filename Original filename supplied by the client.
 * @param array|null  $mimes    Allowed MIME map passed to the check.
 * @return array
 */
add_filter( 'wp_check_filetype_and_ext', static function (
    array $data,
    string $file,
    string $filename,
    ?array $mimes = null
): array {
    $ext = strtolower( (string) pathinfo( $filename, PATHINFO_EXTENSION ) );

    if ( ! isset( SPX_EXTRA_MIMES[ $ext ] ) ) {
        return $data;
    }

    // If the default check already resolved cleanly, nothing to do.
    if ( ! empty( $data['ext'] ) && ! empty( $data['type'] ) ) {
        return $data;
    }

    // Use finfo to inspect the actual file contents before overriding.
    // Only proceed when the detected MIME is one of the known legitimate
    // variants for this extension (e.g. audio/x-wav for .wav), so that a
    // non-matching file renamed to .wav/.mp3/.ico is still rejected.
    // Fail secure: if finfo is unavailable or fails to open, leave the
    // default rejection in place rather than overriding without validation.
    if ( ! function_exists( 'finfo_open' ) ) {
        return $data;
    }

    $finfo = finfo_open( FILEINFO_MIME_TYPE );
    if ( false === $finfo ) {
        return $data;
    }

    try {
        $detected = finfo_file( $finfo, $file );
    } finally {
        finfo_close( $finfo );
    }

    if ( ! isset( SPX_FINFO_VARIANTS[ $ext ] ) ) {
        return $data;
    }

    $acceptable = SPX_FINFO_VARIANTS[ $ext ];
    if ( false === $detected || ! in_array( $detected, $acceptable, true ) ) {
        // File contents do not match any known variant; leave the
        // default rejection in place.
        return $data;
    }

    $data['ext']  = $ext;
    $data['type'] = SPX_EXTRA_MIMES[ $ext ];

    return $data;
}, 10, 4 );
