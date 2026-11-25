<?php

namespace Vendor\HybridCrypto\Facades;

use Illuminate\Support\Facades\Facade;

class HybridCrypto extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'hybrid-crypto';
    }
}
