<?php
namespace iboxs\waf\lib;
trait MatchLib{
    public $matchList=[];

    public function matchCheck($value){
        if(is_array($value)){
            foreach($value as $v){
                $result=$this->checkAuth($v);
                if($result==false){
                    return false;
                }
            }
        }
        if(!is_string($value)){
            return true;
        }
        foreach($this->matchList as $m){
            $match=preg_match($m, $value,$matchs);
            if($match>0){
                return false;
            }
        }
        return true;
    }
}
?>