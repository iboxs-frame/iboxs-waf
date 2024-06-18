<?php
namespace iboxs\waf;

class WAF
{
    public static function install(){
        if(function_exists('config_path')){
            $path=config_path();
            if(!file_exists($path.'/waf.php')){
                copy(__DIR__.'/../test/waf.php',$path.'/waf.php');
            }
        }
        return true;
    }
}