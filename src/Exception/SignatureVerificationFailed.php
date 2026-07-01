<?php

declare(strict_types=1);

namespace K2gl\SignedNote\Exception;

use RuntimeException;

/** No signature on a note verified against a known key. */
final class SignatureVerificationFailed extends RuntimeException implements SignedNoteException {}
