<?php
namespace iboxs\waf\rule;

use Exception;
use iboxs\Request;

/**
 * 目录保护
 */
class PATH{
    public $matchList=[
        '/\.(htaccess|mysql_history|bash_history|DS_Store|idea|user\.ini)/',
        '/\.(bak|inc|old|mdb|sql|php~|swp|java|class)$/',
        '/(vhost|bbs|host|wwwroot|www|site|root|backup|data|ftp|db|admin|website|web).*\.(rar|sql|zip|tar\.gz|tar)/',
        '/(hack|shell|spy|phpspy)\.php$/',
        '/(attachments|css|uploadfiles|static|forumdata|cache|avatar)\w+\.(php|jsp)/',
        '/\.\./',
        '/\*/',
        '/(?:etc\/\W*passwd)/',
        ''
    ];

    public function handle(Request $request){
        $url=$request->url();
        foreach ($this->matchList as $value) {
            if(preg_match($value,$url)){
                return false;
            }
        }
        return true;
    }
}