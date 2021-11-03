<?php
return [
    'issue_by' => null,

    'key' => [
        'public' => storage_path('public.key'),
        'private' => storage_path('private.key')
    ],

    'expire' => 300,

    'user_mapper' => \Jiaxincui\JWTAuth\GenericUserMapper::class,
];
