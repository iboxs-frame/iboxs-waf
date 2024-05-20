<?php
namespace iboxs\waf\rule;

use Exception;
use iboxs\Request;
use iboxs\waf\lib\BaseRule;

/**
 * 防远程代码执行
 */
class CODE extends BaseRule {
    public $matchList=[
        '/echo\s(\w+)/',
        '/exec\s\(\'\w+/',
        '/exec\s\(\w+/',
        '/(?:define|eval|file_get_contents|include|require|require_once|shell_exec|phpinfo|system|passthru|preg_\w+|execute|echo|print|print_r|var_dump|(fp)open|alert|showmodaldialog)\(/',
        '/(gopher|doc|php|glob|^file|phar|zlib|ftp|ldap|dict|ogg|data)\:\//',
        '/\:\$/',
        '/\$\{/',
        '/(invokefunction|call_user_func_array|\sthink\s)/',
        '/base64_decode\(/',
        '/(?:define|eval|file_get_contents|include|require|require_once|shell_exec|phpinfo|system|passthru|char|chr|preg_\w+|execute|echo|print|print_r|var_dump|(fp)open|alert|showmodaldialog)\(/',
        '/\$_(GET|post|cookie|files|session|env|phplib|GLOBALS|SERVER)\[/',
    ];

    public function handle(Request $request){
        $param=request()->param();
        foreach($param as $k=>$v){
            if(!is_string($v)){
                if(is_array($v)){
                    $result=$this->matchCheck($v);
                    if($result==false){
                        return false;
                    }
                }
                continue;
            } else{
                $check=$this->matchCheck($v);
                if($check==false){
                    return false;
                }
                $check=$this->matchCheck($k);
                if($check==false){
                    return false;
                }
            }
        }
        return true;
    }

    
}