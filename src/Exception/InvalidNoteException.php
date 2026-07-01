<?php

declare(strict_types=1);

namespace K2gl\SignedNote\Exception;

use RuntimeException;

/** A note, or a note key, is malformed. */
final class InvalidNoteException extends RuntimeException implements SignedNoteException {}
