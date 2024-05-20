<?php
namespace iboxs\waf\lib;
class Handle{
    public function handle($rule,$request){
        // dd($rule,$request);
        $logsPath=root_path('runtime/waf/logs');
        if(!is_dir($logsPath)){
            mkdir($logsPath,0777,true);
            chmod($logsPath,0777);
        }
        $logs=root_path('runtime/waf/logs/').date('Y-m-d').'.log';
        $log="[".date('Y-m-d H:i:s')."]RULE:{$rule},\r\nURL:{$request->url(true)}\r\nREQUEST:". json_encode($request->param()).",IP[". request()->ip() ."]";
        file_put_contents($logs,$log.PHP_EOL,FILE_APPEND);
        return true;
    }
}