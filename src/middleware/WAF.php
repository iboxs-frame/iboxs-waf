<?php
declare (strict_types = 1);

namespace iboxs\waf\middleware;

use Closure;
use iboxs\Config;
use iboxs\waf\lib\Handle;

class WAF
{
    public $wafConfig;
    public $config;

    public function __construct(Config $config)
    {
        $this->wafConfig=config('waf');
        $this->config=$config;
    }

    public function handle($request, Closure $next, ? array $header = [])
    {
        $ipWhite=$this->ipWhite();
        if($ipWhite==true){
            return $next($request);
        }
        $ipBlack=$this->ipBlack();
        if($ipBlack){
            return $this->banRequest('BlackIP',$request);
        }
        $method=$request->method();
        $methodRule=$this->wafConfig['method'][$method]??null;
        $rule=[];
        if($methodRule!=null&&$methodRule['check']==true){
            $rule=$this->wafConfig['method'][$method]['rule']??[];
        }
        $rule=array_merge($rule,$this->wafConfig['rule']);
        $rule=array_unique($rule);
        if(count($rule)<1){
            return $next($request);
        }
        foreach($rule as $r){
            $class=new $r($this->config);
            $result=$class->handle($request);
            if($result==false){
                return $this->banRequest($r,$request);
            }
        }
        return $next($request);
    }

    private function banRequest($r,$request){
        $response=$this->wafConfig['response'][$r]??null;
        if($response==null){
            $tpl=__DIR__."/../tpl/refuse.tpl";
            $code=403;
        } else{
            $tpl=$response['tpl']??(__DIR__."/../tpl/refuse.tpl");
            $code=$response['code']??403;
        }
        if(!file_exists($tpl)){
            return response('模板文件不存在',$code,[],'html',false);
        }
        $response=file_get_contents($tpl);
        $handle=$this->wafConfig['handle']??(Handle::class);
        if(class_exists($handle)){
            $handleClass=new $handle();
            $handleClass->handle($r,$request);
        }
        return response($response,$code,[],'html',false);
    }

    public function ipWhite(){
        $ip=request()->ip();
        $ipwhite=$this->wafConfig['iptables']??[];
        $morenIpWhite=$this->wafConfig['iptables']['white']??[];
        if(in_array($ip,$morenIpWhite)){
            return true;
        }
        if($ipwhite==[]){
            return false;
        }
        $type=$ipwhite['type'];
        switch($type){
            case 'model':
                $model=$ipwhite['model'];
                if(!class_exists($model)){
                    return false;
                }
                $model=new $model();
                $exites=$model->where('type','white')->where('ip',$ip)->exists();
                break;
        }
        return $exites;
    }

    private function ipBlack(){
        $ip=request()->ip();
        $ipBlack=$this->wafConfig['iptables']??[];
        $morenIpBlack=$this->wafConfig['iptables']['black']??[];
        if(in_array($ip,$morenIpBlack)){
            return true;
        }
        if($ipBlack==[]){
            return false;
        }
        $type=$ipBlack['type'];
        switch($type){
            case 'model':
                $model=$ipBlack['model'];
                if(!class_exists($model)){
                    return false;
                }
                $model=new $model();
                $exites=$model->where('type','black')->where('ip',$ip)->exists();
                break;
        }
        return $exites;
    }
}