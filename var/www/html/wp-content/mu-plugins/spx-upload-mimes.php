<?php
declare(strict_types=1);

/**
 * Plugin Name: SPX Upload MIME Types
 * Description: Extends the WordPress Media Library allowlist to permit a fixed
 *              set of audio, image, video, and vCard file types, and reconciles
 *              the non-canonical MIME strings that libmagic returns for several
 *              of them on Ubuntu 22/24 with PHP 8.2/8.3. Installed as a
 *              must-use plugin so the allowlist is always active regardless of
 *              which regular plugins are enabled.
 *
 * Background
 * ----------
 * WordPress verifies that an upload's declared extension matches the MIME type
 * that PHP's fileinfo/libmagic extension detects from the file contents. Two
 * problems break legitimate uploads:
 *
 *   1. Some extensions (e.g. ICO) are deliberately absent from WordPress's
 *      default upload_mimes allowlist, so the upload is rejected before the
 *      content check even runs.
 *
 *   2. libmagic returns non-canonical MIME strings for several formats
 *      (e.g. WAV -> audio/x-wav where WordPress expects audio/wav,
 *      MP3 -> audio/x-mpeg where WordPress expects audio/mpeg), causing a
 *      mismatch that vetoes an otherwise valid upload.
 *
 * Two hooks address these in order:
 *   - upload_mimes              adds the managed extensions to the allowlist.
 *   - wp_check_filetype_and_ext supplies the canonical MIME string when the
 *                               default check fails AND fileinfo independently
 *                               confirms the contents are a genuine instance of
 *                               the type (fail-secure: a foreign file merely
 *                               renamed to a managed extension is still
 *                               rejected).
 *
 * Standard Media Library uploads (/wp-admin/async-upload.php or
 * /wp-json/wp/v2/media) are used for these types. The TUS resumable endpoint
 * (/files/) is reserved exclusively for Submission Core audio ingestion and
 * must NOT be used for Media Library uploads.
 *
 * NOTE: Adjust the namespace below to match the platform standards repo's
 * canonical root namespace before committing.
 */

namespace Starisian\Sparxstar\MimeTypes;

\defined( 'ABSPATH' ) || exit;

/**
 * Registers and implements the Media Library MIME allowlist extensions.
 *
 * All behaviour is stateless, so the hook callbacks are exposed as static
 * methods. Naming them (rather than using anonymous closures) means any fatal
 * raised inside them is attributed to this class in the stack trace instead of
 * the opaque "{closure}".
 */
final class UploadMimeTypes {

    /**
     * Canonical extension => MIME map for every type this plugin unlocks.
     *
     * Single source of truth shared by both the upload_mimes allowlist filter
     * and the wp_check_filetype_and_ext fileinfo-override filter.
     *
     * @var array<string, string>
     */
    private const EXTRA_MIMES = [
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
        'vcf'  => 'text/vcard',
    ];

    /**
     * MIME strings that fileinfo/libmagic may legitimately return for genuine
     * files of each managed extension. The override is applied only when the
     * detected MIME is one of these known-good variants, so a foreign file
     * renamed to a managed extension is still rejected by content validation.
     *
     * @var array<string, list<string>>
     */
    private const FINFO_VARIANTS = [
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
        'vcf'  => [ 'text/vcard', 'text/x-vcard' ],
    ];

    /**
     * Wire up the filters. Called once when this file loads.
     */
    public static function register(): void {
        \add_filter( 'upload_mimes', [ self::class, 'allowExtraMimes' ] );
        \add_filter( 'wp_check_filetype_and_ext', [ self::class, 'overrideFiletypeCheck' ], 10, 4 );
    }

    /**
     * Add the managed extensions to the upload allowlist.
     *
     * Core always passes an array here (the result of wp_get_mime_types()),
     * so the non-nullable array hint is safe for this hook.
     *
     * @param array<string, string> $mimes Existing extension => MIME map.
     * @return array<string, string>
     */
    public static function allowExtraMimes( array $mimes ): array {
        foreach ( self::EXTRA_MIMES as $ext => $mime ) {
            $mimes[ $ext ] = $mime;
        }

        return $mimes;
    }

    /**
     * Override the fileinfo verdict for managed extensions when, and only when,
     * the file contents independently verify as a genuine instance of the type.
     *
     * The $mimes parameter is nullable because core declares it with a null
     * default (wp_check_filetype_and_ext( $file, $filename, $mimes = null, ... ))
     * and passes that null straight through on the REST media path. A
     * non-nullable array hint here is a latent fatal that takes down every
     * upload, not just the managed types.
     *
     * @param array{ext: string|false, type: string|false, proper_filename: string|false} $data
     * @param string                     $file     Absolute path to the temp upload.
     * @param string                     $filename Original client filename.
     * @param array<string, string>|null $mimes    Allowed MIME map, or null.
     * @return array{ext: string|false, type: string|false, proper_filename: string|false}
     */
    public static function overrideFiletypeCheck(
        array $data,
        string $file,
        string $filename,
        ?array $mimes = null
    ): array {
        $ext = \strtolower( (string) \pathinfo( $filename, \PATHINFO_EXTENSION ) );

        // Not a managed extension: leave the default verdict untouched.
        if ( ! isset( self::EXTRA_MIMES[ $ext ] ) ) {
            return $data;
        }

        // Default check already resolved cleanly: nothing to override.
        if ( ! empty( $data['ext'] ) && ! empty( $data['type'] ) ) {
            return $data;
        }

        // Fail secure: without fileinfo we cannot verify contents, so leave
        // the default rejection in place rather than override blindly.
        if ( ! \function_exists( 'finfo_open' ) ) {
            return $data;
        }

        $finfo = \finfo_open( \FILEINFO_MIME_TYPE );
        if ( false === $finfo ) {
            return $data;
        }

        try {
            $detected = \finfo_file( $finfo, $file );
        } finally {
            \finfo_close( $finfo );
        }

        // Defensive: no known variant table for this extension.
        if ( ! isset( self::FINFO_VARIANTS[ $ext ] ) ) {
            return $data;
        }

        // Detected MIME must be a known-good variant for this extension,
        // otherwise the file is a foreign type wearing a managed extension.
        if ( false === $detected || ! \in_array( $detected, self::FINFO_VARIANTS[ $ext ], true ) ) {
            return $data;
        }

        $data['ext']  = $ext;
        $data['type'] = self::EXTRA_MIMES[ $ext ];

        return $data;
    }
}

UploadMimeTypes::register();
