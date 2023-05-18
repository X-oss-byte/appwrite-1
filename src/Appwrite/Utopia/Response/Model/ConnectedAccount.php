<?php

namespace Appwrite\Utopia\Response\Model;

use Appwrite\Utopia\Response;
use Appwrite\Utopia\Response\Model;

class ConnectedAccount extends Model
{
    public function __construct()
    {
        $this
            ->addRule('$id', [
                'type' => self::TYPE_STRING,
                'description' => 'Connected Account ID.',
                'default' => '',
                'example' => '5e5ea5c16897e',
            ])
            ->addRule('$createdAt', [
                'type' => self::TYPE_DATETIME,
                'description' => 'Connected Account creation date in ISO 8601 format.',
                'default' => '',
                'example' => self::TYPE_DATETIME_EXAMPLE,
            ])
            ->addRule('$updatedAt', [
                'type' => self::TYPE_DATETIME,
                'description' => 'Connected Account update date in ISO 8601 format.',
                'default' => '',
                'example' => self::TYPE_DATETIME_EXAMPLE,
            ])
            ->addRule('userId', [
                'type' => self::TYPE_STRING,
                'description' => 'User ID.',
                'default' => '',
                'example' => '5e5bb8c16897e',
            ])
            ->addRule('provider', [
                'type' => self::TYPE_STRING,
                'description' => 'Connected Account Provider.',
                'default' => '',
                'example' => 'email',
            ])
            ->addRule('status', [
                'type' => self::TYPE_STRING,
                'description' => 'Connection status. Can be connected or disconnected',
                'default' => '',
                'example' => 'connected',
            ])
            ->addRule('providerUid', [
                'type' => self::TYPE_STRING,
                'description' => 'ID of the User in the Connected Account Provider.',
                'default' => '',
                'example' => 'user@example.com',
            ])
            ->addRule('providerAccessToken', [
                'type' => self::TYPE_STRING,
                'description' => 'Connected Account Provider Access Token.',
                'default' => '',
                'example' => 'MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3',
            ])
            ->addRule('providerAccessTokenExpiry', [
                'type' => self::TYPE_DATETIME,
                'description' => 'The date of when the access token expires in ISO 8601 format.',
                'default' => '',
                'example' => self::TYPE_DATETIME_EXAMPLE,
            ])
            ->addRule('providerRefreshToken', [
                'type' => self::TYPE_STRING,
                'description' => 'Connected Account Provider Refresh Token.',
                'default' => '',
                'example' => 'MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3',
            ])
        ;
    }

    /**
     * Get Name
     *
     * @return string
     */
    public function getName(): string
    {
        return 'Connected Account';
    }

    /**
     * Get Type
     *
     * @return string
     */
    public function getType(): string
    {
        return Response::MODEL_CONNECTED_ACCOUNT;
    }
}
