<?php

namespace Vendor\HybridCrypto;

use Illuminate\Routing\Router;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use Vendor\HybridCrypto\Http\Middleware\HybridCryptoPayloadMiddleware;

class HybridCryptoServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-hybrid-crypto')
            ->hasConfigFile('hybrid-crypto')
            ->hasViews('hybrid-crypto')
            ->hasRoute('hybrid-crypto');
    }

    public function registeringPackage(): void
    {
        $this->app->singleton(HybridCryptoManager::class, function ($app) {
            return new HybridCryptoManager((array) $app['config']->get('hybrid-crypto', []));
        });

        $this->app->singleton('hybrid-crypto', function ($app) {
            return $app->make(HybridCryptoManager::class);
        });
    }

    public function bootingPackage(): void
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('hybrid.crypto', HybridCryptoPayloadMiddleware::class);
    }
}
