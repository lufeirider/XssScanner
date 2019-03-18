package burp;

import com.gargoylesoftware.htmlunit.ScriptException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.javascript.JavaScriptEngine;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.BurpExtender.stdout;

public class XssChecker {
    String url = "";
    List<String> headers = null;
    String body = "";
    String method = "";
    String response_body = "";
    public XssChecker(String url,List<String> headers,String body,String method){
        this.url = url;
        this.headers = headers;
        this.body = body;
        this.method = method;
    }

    /**
     *
     */
    public void send_request() {
        WebClient webClient = new WebClient();
        webClient.getOptions().setJavaScriptEnabled(true);
        webClient.getOptions().setCssEnabled(false);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnScriptError(false);

        //设置连接监听器，实现对返回包的修改，从而hook函数
        new WebConnectionListener(webClient);
        // 这里尝试去取我们设置的JavaScript错误处理器
        final JavaScriptEngine myEngine = new JavaScriptEngine(webClient) {
            @Override
            protected void handleJavaScriptException(final ScriptException scriptException, final boolean triggerOnError) {
                System.out.println(scriptException.getMessage());
                super.handleJavaScriptException(scriptException, triggerOnError);

            }
        };
        webClient.setJavaScriptEngine(myEngine);

        try {

            //获取到原来的request headers，使用原来的request headers发送
            WebRequest request = new WebRequest(new URL(this.url));
            for (String head:this.headers) {
                if (head.contains(":")&&!head.contains("Content-Length"))
                {
                    request.setAdditionalHeader(head.split(":")[0],head.split(":")[1]);

                }
            }

            if(this.method == "POST")
            {
                //post请求设置body
                request.setRequestBody(this.body);
                HtmlPage htmlPage = webClient.getPage(request);
                this.response_body = htmlPage.asXml();
            }else {

                HtmlPage htmlPage = webClient.getPage(request);
                this.response_body = htmlPage.asXml();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        webClient.close();
    }

    public  ArrayList test_all_character(){
        Pattern pattern;
        Matcher matcher;
        boolean match_flag;
        ArrayList<String> result_list = new ArrayList<>();
        //1415926'"<xxx'"xxx>xxx
        //html 逃逸所有符号，不能确定所在位置。有可能单引号逃逸、双引号逃逸、或者属性
        //匹配 <xxx '"xxx="">
        pattern = Pattern.compile("<xxx(.*?)'\"xxx(.*?)>");
        matcher = pattern.matcher(this.response_body);
        match_flag = matcher.find();
        if(match_flag)
        {
                /*
                  <body>
                    <img src="1415926&quot;" xxx'"xxx=""/>
                    '&gt;
                  </body>
                 */
            result_list.add("'  \"  <  >  all is available");
            result_list.add(matcher.group(0));
        }

        return result_list;
    }

    public ArrayList<String> check_js_html_xss(){
        Pattern pattern;
        Matcher matcher;
        boolean match_flag;
        ArrayList<String> result_list = new ArrayList<>();



        //获取script里面的js
        pattern = Pattern.compile("//<!\\[CDATA\\[(.*?)//\\]\\]>",Pattern.DOTALL);
        matcher = pattern.matcher(this.response_body);
        List<String> script_list = new ArrayList<String>();
        while (matcher.find()) {
            script_list.add(matcher.group());
        }




        //检测所有关键字符是否被过滤
        result_list = test_all_character();
        if(!result_list.isEmpty()){return result_list;}

        //html 逃逸尖括号
        //匹配 <xxx \\'\\\"xxx="">
        pattern = Pattern.compile("<xxx (.*?)xxx=\"\"(.*?)>");
        matcher = pattern.matcher(this.response_body);
        match_flag = matcher.find();
        if(match_flag)
        {
            /*
          <body>
            jsonpCallback({"appId":"wxf98b3dd05ebdbbb5","nonceStr":"3IUD3tCOC1oLUgL2","timestamp":1552880916,"url":"1415926\\'\\\"
            <xxx \\'\\\"xxx="">
              xxx","signature":"51b5541459201685a8b0f96be7314e13a4dc6745","rawString":"jsapi_ticket=bxLdikRXVbTPdHSM05e5uw4kcDrusCLB2V1sGheIfWKaU97l-chycHG-DShwMZ-F1GDaz03AIPj7_ticgMIBxw&amp;noncestr=3IUD3tCOC1oLUgL2��tamp=1552880916&amp;url=1415926\\'\\\"
              <xxx \\'\\\"xxx="">
                xxx"})
              </xxx>
            </xxx>
          </body>
             */
            result_list.add("out label <> can escape.");
            result_list.add(matcher.group(0));
            return result_list;
        }

        //html 双引号逃逸
        //匹配 <xxx '"xxx="">.*?"&gt;
        //http://127.0.0.1/in_label_value_single_xss.php?url=1415926'"<xxx'"xxx>xxx
        pattern = Pattern.compile("xxx(.*?)\"(.*?)xxx=\"\"(.*?)>.*?\"&gt;",Pattern.DOTALL);
        matcher = pattern.matcher(this.response_body);
        match_flag = matcher.find();
        if(match_flag)
        {
            /*
              <body>
                <img src="1415926'"/>
                <xxx '"xxx="">
                  " alt="1.jpg"&gt;
                </xxx>
              </body>
             */
            result_list.add("in label value html-xss:' can escape.");
            result_list.add(matcher.group(0));
            return result_list;
        }

        //html 单引号逃逸
        //匹配 <img src="1415926" "<xxx'"xxx=""/>.*?'&gt;
        //http://127.0.0.1/in_label_value_double_xss.php?url=1415926'"<xxx'"xxx>xxx
        pattern = Pattern.compile("xxx(.*?)'(.*?)xxx=\"\"(.*?)>.*?'&gt;",Pattern.DOTALL);
        matcher = pattern.matcher(this.response_body);
        match_flag = matcher.find();
        if(match_flag)
        {
            /*
              <body>
                <img src="1415926" "<xxx'"xxx=""/>
                '&gt;
              </body>
             */
            result_list.add("in label value html-xss: ' can escape.");
            result_list.add(matcher.group(0));
            return result_list;
        }

        //html attribute
        //匹配 <xxx'"xxx=""/>.*?xxx&gt;
        //http://127.0.0.1/in_label_attr_xss.php?url=1415926'"<xxx'"xxx>xxx
        pattern = Pattern.compile("xxx(.*?)'(.*?)xxx=\"\"(.*?)>.*?xxx&gt;",Pattern.DOTALL);
        matcher = pattern.matcher(this.response_body);
        match_flag = matcher.find();
        if(match_flag)
        {
            /*
              <body>
                <img src="1" 1415926'"<xxx'"xxx=""/>
                xxx&gt;
              </body>
             */
            result_list.add("in label attribute html-xss");
            result_list.add(matcher.group(0));
            return result_list;
        }


        //检测js中没有分隔符符号的情况，var a = test
        String js_str = script_list.toString();
        pattern = Pattern.compile("(.*?)1415926(.*?)xxx(.*?)xxx");
        matcher = pattern.matcher(script_list.toString());
        match_flag = matcher.find();
        if(match_flag)
        {
            String match_str = matcher.group(0);
            int single_position = match_str.substring(0,matcher.group(0).indexOf("1415926")).indexOf("'");
            int double_position = match_str.substring(0,matcher.group(0).indexOf("1415926")).indexOf("\"");

            if(single_position == double_position &&  single_position == -1)
            {
                result_list.add("js-context xss");
                result_list.add(matcher.group(0));
                return result_list;
            }

            //第一个双引号出现的位置在第一个单引号的位置后面，则说明是单引号包含的
            if( (double_position>-1 && single_position>-1 && double_position > single_position) || single_position>-1)
            {
                pattern = Pattern.compile("(.*?)1415926(.*?)'(.*?)xxx(.*?)xxx");
                matcher = pattern.matcher(this.response_body);
                match_flag = matcher.find();
                if(match_flag)
                {
                    result_list.add("js-context xss ' can escape.");
                    result_list.add(matcher.group(0));
                    return result_list;
                }
            }

            //第一个出现单引号的位置在第一个双引号的位置后面，则说明是双引号包含的
            if((double_position>-1 && single_position>-1 && double_position < single_position) || double_position>-1)
            {
                pattern = Pattern.compile("(.*?)1415926(.*?)\"(.*?)xxx(.*?)xxx");
                matcher = pattern.matcher(this.response_body);
                match_flag = matcher.find();
                if(match_flag)
                {
                    result_list.add(" js-context xss \" can escape.");
                    result_list.add(matcher.group(0));
                    return result_list;
                }
            }

        }

        //检测dom location href src
        pattern = Pattern.compile("(a|frame)(.*?)(href|src)=\"1415926");
        matcher = pattern.matcher(this.response_body);
        match_flag = matcher.find();
        if(match_flag)
        {
            result_list.add("note frame src or a href.");
            result_list.add(matcher.group(0));
            return result_list;
        }

        //检测dom eval
        pattern = Pattern.compile("eval(.*?)1415926");
        matcher = pattern.matcher(this.response_body);
        match_flag = matcher.find();
        if(match_flag)
        {
            result_list.add("notice eval()");
            result_list.add(matcher.group(0));
            return result_list;
        }

        //检测dom settimeout
        pattern = Pattern.compile("settimeout(.*?)1415926");
        matcher = pattern.matcher(this.response_body);
        match_flag = matcher.find();
        if(match_flag)
        {
            result_list.add("notice settimeout()");
            result_list.add(matcher.group(0));
            return result_list;
        }

        //检测dom eval
        pattern = Pattern.compile("location(.*?)1415926");
        matcher = pattern.matcher(this.response_body);
        match_flag = matcher.find();
        if(match_flag)
        {
            result_list.add("notice location()");
            result_list.add(matcher.group(0));
            return result_list;
        }



        return result_list;

    }
}
