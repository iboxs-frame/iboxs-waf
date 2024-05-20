<?php
namespace iboxs\waf\rule;

use Exception;
use iboxs\Request;
use iboxs\waf\lib\BaseRule;

/**
 * 目录保护
 */
class XSS extends BaseRule{
    public $matchList=[
        '/\<(iframe|script|body|img|layer|meta|style|base|object|input)/'
    ];

    public function handle(Request $request){
        $params=request()->param();
        foreach($params as $key=>$val){
            if(!is_string($val)){
                if(is_array($val)){
                    $result=$this->matchCheck($val);
                    if($result==false){
                        return false;
                    }
                }
                continue;
            } else{
                $value=strtolower($val);
                foreach($this->matchList as $m){
                    $match=preg_match($m, $value,$matchs);
                    if($match>0){
                        return false;
                    }
                }
                foreach($this->matchList as $s){
                    $s=strtolower($s);
                    if(substr_count($value,$s)>0){
                        return false;
                    }
                }
            }
        }
        return true;
    }
}