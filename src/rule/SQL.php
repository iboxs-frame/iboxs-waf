<?php
namespace iboxs\waf\rule;

use iboxs\Request;
use iboxs\waf\lib\BaseRule;

/**
 * 防SQL注入
 */
class SQL extends BaseRule {
    
    protected $sqlAuth=[
        '\' union select',
        '" union select',
        '\' OR (SELECT',
        'SELECT*FROM',
        'SELECT * FROM',
        'SLEEP(',
        'EXEC '
    ];

    public $matchList=[
        '/select\s*(\w+|\*)\s*from /',
        '/update\s*(w+)\s*set/',
        '/delete\s*from\s*(w+)/',
        '/insert\s*into\s*(w+)\s*values/',
        '/drop\s*(w+)/',
        '/create\s*table\s*/',
        '/create\s*index\s*/',
        '/(?:(union(.*?)select))/',
        "/\s+(or|xor|and)\s+.*(=|<|>|'|\")/",
        '/select.+(from|limit)/',
        '/sleep\((\s*)(\d*)(\s*)\)/',
        '/(?:(union(.*?)select))/',
        '/benchmark\((.*)\,(.*)\)/',
        '/(?:from\W+information_schema\W)/',
        '/(?:(?:current_)user|database|schema|connection_id)\s*\(/',
        '/into(\s+)+(?:dump|out)file\s*/',
        '/group\s+by.+\(/'
    ];

    public function handle(Request $request){
        $params=request()->param();
        foreach($params as $key=>$val){
            if(!is_string($val)){
                if(is_array($val)){
                    foreach($val as $v){
                        $result=$this->matchCheck($val);
                        if($result==false){
                            return false;
                        }
                    }
                }
                continue;
            } else{
                $value=strtolower($val);
                $result=$this->matchCheck($value);
                if($result==false){
                    return false;
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
?>