<?php

namespace Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Vendor\HybridCrypto\HybridCryptoServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            HybridCryptoServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('hybrid-crypto.paths.p384_private_key', 'framework/testing/hybrid-crypto/p384_private.pem');
        $app['config']->set('hybrid-crypto.paths.p256_private_key', 'framework/testing/hybrid-crypto/p256_private.pem');
        $app['config']->set('hybrid-crypto.paths.ecdh_keypair', 'framework/testing/hybrid-crypto/ecdh_keypair.json');
        $app['config']->set('hybrid-crypto.paths.mlkem768_keypair', 'framework/testing/hybrid-crypto/mlkem768_keypair.json');
        $app['config']->set('hybrid-crypto.kdf.info', 'laravel-hybrid-crypto:test');
    }
}
