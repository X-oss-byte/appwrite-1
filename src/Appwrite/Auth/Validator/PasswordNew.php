<?php

namespace Appwrite\Auth\Validator;

use Appwrite\Auth\Auth;
use Utopia\Validator;
use Utopia\Database\Document;

class PasswordNew extends Validator
{
    protected ?Document $project;
    
    protected ?Document $user;

    protected array $dictionary;

    protected bool $strict;

    protected string $description = 'Password must be at least 8 characters';

    public function __construct(
        Document $project = null, 
        Document $user = null, 
        array $dictionary = [], 
        bool $strict = false
    ) {
        $this->project = $project;
        $this->user = $user;
        $this->dictionary = $dictionary;
        $this->strict = $strict;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function isValid($value): bool
    {
        /* Base password rules */
        if (!\is_string($value) || \strlen($value) < 8) {
            $this->description = 'Password must be at least 8 characters';
            return false;
        }

        /* Dictionary check */
        if ($this->project && !$this->project->isEmpty()) {
            if (!$this->isValidDictionaryCheck($this->project, $value)) {
                $this->description = 'Password should not be one of the commonly used passwords';
                return false;
            }
        }

        if ($this->project && !$this->project->empty() && $this->user && !$this->user->empty()) {
            /* History check */
            if (!$this->isValidHistoryCheck($this->project, $this->user, $value)) {
                $this->description = 'Password shouldn\'t be in the history.';
                return false;
            }

            /* Personal data check */
            if (!$this->isValidPersonalDataCheck($this->project, $this->user, $value)) {
                $this->description = 'Password must not include any personal data like your name, email, phone number, etc.';
                return false;
            }
        }

        return true;
    }

    private function isValidDictionaryCheck(Document $project, string $value): bool
    {
        $dictionaryEnabled = $project->getAttribute('auths', [])['passwordDictionary'] ?? false;
        if ($dictionaryEnabled && array_key_exists($value, $this->dictionary)) {
            return false;
        }
        return true;
    }

    private function isValidHistoryCheck(Document $project, Document $user, string $value): bool
    {
        $algo = $user->getAttribute('hash');
        $history = $user->getAttribute('passwordHistory', []);
        $algoOptions = $user->getAttribute('hashOptions');
        $historyLimit = $project->getAttribute('auths', [])['passwordHistory'] ?? 0;
        
        if ($historyLimit > 0) {
            foreach ($history as $hash) {
                if (Auth::passwordVerify($value, $hash, $algo, $algoOptions)) {
                    return false;
                }
            }
        }    
        return true;
    }

    private function isValidPersonalDataCheck(Document $project, Document $user, string $value): bool
    {
        $personalDataEnabled = $project->getAttribute('auths', [])['disallowPersonalData'] ?? false;
        $userId = $user->getId();
        $email = $user->getAttribute('email');
        $name = $user->getAttribute('name');
        $phone = $user->getAttribute('phone');

        if (!$this->strict) {
            $value = strtolower($value);
            $userId = strtolower($userId);
            $email = strtolower($email);
            $name = strtolower($name);
            $phone = strtolower($phone);
        }

        if (
            ($userId && strpos($value, $userId) !== false) ||
            ($email && strpos($value, $email) !== false) ||
            ($email && strpos($value, explode('@', $email)[0] ?? '') !== false) ||
            ($name && strpos($value, $name) !== false) ||
            ($phone && strpos($value, str_replace('+', '', $phone)) !== false) ||
            ($phone && strpos($value, $phone) !== false)
        ) {
            return false;
        }

        return true;
    }


    public function isArray(): bool
    {
        return false;
    }

    public function getType(): string
    {
        return self::TYPE_STRING;
    }
}
