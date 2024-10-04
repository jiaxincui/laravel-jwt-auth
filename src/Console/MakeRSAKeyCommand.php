<?php

namespace Jiaxincui\JWTAuth\Console;

use Illuminate\Console\Command;

class MakeRSAKeyCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'make:rsakey
                                      {--force : Overwrite keys they already exist}
                                      {--length=4096 : The length of the private key}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create the encryption keys for API authentication';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     */
    public function handle()
    {
        [$publicKeyPath, $privateKeyPath] = [
            config('jwtauth.key.public'),
            config('jwtauth.key.private'),
        ];

        if ((file_exists($publicKeyPath) || file_exists($privateKeyPath)) && !$this->option('force')) {
            $this->error('RSA keys already exist. Use the --force option to overwrite them.');
        } else {
            $privateKey = '';
            $config = [
                'digest_alg' => 'sha256',
                'private_key_bits' => $this->input ? (int) $this->option('length') : 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA
            ];

            $res = openssl_pkey_new($config);

            openssl_pkey_export($res, $privateKey);

            $details = openssl_pkey_get_details($res);

            $publicKey = $details['key'];

            file_put_contents($publicKeyPath, $publicKey);
            file_put_contents($privateKeyPath, $privateKey);

            $this->info('RSA keys generated successfully.');
        }
    }
}
