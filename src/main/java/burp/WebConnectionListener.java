package burp;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.util.FalsifyingWebConnection;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.BurpExtender.first_flag;

public class WebConnectionListener extends FalsifyingWebConnection {

    public WebConnectionListener(WebClient webClient) throws IllegalArgumentException {
        super(webClient);
    }

    @Override
    public WebResponse getResponse(WebRequest request) throws IOException {


        WebResponse response = super.getResponse(request);

        String url = response.getWebRequest().getUrl().toString();

        Pattern pattern;
        Matcher matcher;
        String modify_response;

        //修改源码进行hook
        pattern = Pattern.compile("location(\\W*?)=");
        matcher = pattern.matcher(response.getContentAsString());
        modify_response = matcher.replaceAll("location.href=");

        //修改源码进行hook
        pattern = Pattern.compile("location.replace");
        matcher = pattern.matcher(response.getContentAsString());
        modify_response = matcher.replaceAll("_replace");

        //主要是为了第一个页面进行添加hook的js代码，如果不这样设置，导致第二请求的包js被修改。
        if(first_flag)
        {
            first_flag = false;
            return createWebResponse(response.getWebRequest(), "<script>\n"
                    +"function append(type,payload)\n" +
                    "{\n" +
                    "    if(payload.indexOf(\"1415926\")>-1)\n" +
                    "    {\n" +
                    "        var para=document.createElement(\"p\");\n" +
                    "        var node=document.createTextNode(type + payload);\n" +
                    "        para.appendChild(node);\n" +
                    "        var element=document.getElementsByTagName(\"html\")[0];\n" +
                    "        element.appendChild(para);\n" +
                    "    }\n" +
                    "}\n" +
                    "//重新定义一个方法进行hook\n" +
                    "var _eval = eval;\n" +
                    "window.eval = function(string) {\n" +
                    "    append(\"eval\",string);\n" +
                    "    _eval(string);\n" +
                    "};\n" +
                    "//重新定义一个方法进行hook\n" +
                    "var _setTimeout = setTimeout;\n" +
                    "window.setTimeout = function(code,millisec) {\n" +
                    "    append(\"setTimeout\",code);\n" +
                    "    _setTimeout(code,millisec);\n" +
                    "};\n" +
                    "//重新定义一个方法进行hook\n" +
                    "var _localStorage = localStorage;\n" +
                    "localStorage.setItem = function(key,value){\n" +
                    "\tappend(\"localStorage\",value);\n" +
                    "\t_localStorage[key] = value;\n" +
                    "}\n" +
                    "//无法直接hook，更改源码里面的方法，再进行hook\n" +
                    "var _replace = function(url)\n" +
                    "{\n" +
                    "    append(\"location.replace\",url);\n" +
                    "};\n" +
                    "//监控变量\n" +
                    "location.__defineSetter__('href', function(url) {\n" +
                    "    append(\"location\",url);\n" +
                    "});\n" +
                    "//监控变量\n" +
                    "document.__defineSetter__('cookie', function(url) {\n" +
                    "    append(\"cookie\",url);\n" +
                    "});"
                    +"</script>" + modify_response, response.getContentType(), response.getStatusCode(), "Ok");
        }else
        {
            return createWebResponse(response.getWebRequest(), modify_response, response.getContentType(), response.getStatusCode(), "Ok");
        }




/*
<script>
function append(type,payload)
{
    if(payload.indexOf("1415926")>-1)
    {
        var para=document.createElement("p");
        var node=document.createTextNode(type + payload);
        para.appendChild(node);
        var element=document.getElementsByTagName("html")[0];
        element.appendChild(para);
    }
}
//重新定义一个方法进行hook
var _eval = eval;
window.eval = function(string) {
    append("eval",string);
    _eval(string);
};
//重新定义一个方法进行hook
var _setTimeout = setTimeout;
window.setTimeout = function(code,millisec) {
    append("setTimeout",code);
    _setTimeout(code,millisec);
};
//重新定义一个方法进行hook,localStorage.setItem(key,value)会递归，所以使用字典形式赋值
var _localStorage = localStorage;
localStorage.setItem = function(key,value){
	append("localStorage",value);
	_localStorage[key] = value;
}
//无法直接hook，更改源码里面的方法，再进行hook
var _replace = function(url)
{
    append("location.replace",url);
};
//监控变量
location.__defineSetter__('href', function(url) {
    append("location",url);
});
//监控变量
document.__defineSetter__('cookie', function(url) {
    append("cookie",url);
});
</script>
*/
    }
}
