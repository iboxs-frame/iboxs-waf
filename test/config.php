<?php

use iboxs\waf\lib\Handle;
use iboxs\waf\rule\CODE;
use iboxs\waf\rule\SQL;
use iboxs\waf\rule\{XSS, PATH};

return [
    'rule' => [
        SQL::class,
        CODE::class,
        XSS::class,
        PATH::class
    ],
    'method' => [
        'GET' => [
            'check' => true,
            'rule' => [
                SQL::class
            ]
        ]
    ],
    'response' => [
        (SQL::class) => [
            // 'tpl'=>'异常',
            'code' => 403,
            'ajax' => [
                'code' => 403,
                'msg' => '异常'
            ]
        ]
    ],
    'handle' => Handle::class,
];
