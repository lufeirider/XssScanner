package dom_xss;

import com.gargoylesoftware.htmlunit.ScriptException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.javascript.JavaScriptEngine;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class dom_xss {
    public static boolean first_flag = true;
    //1415926<>
    public static void test_all_character(String content){
        Pattern pattern;
        Matcher matcher;
        boolean match_flag;
        //html 逃逸所有符号，不能确定所在位置。有可能单引号逃逸、双引号逃逸、或者属性
        //匹配 <ttt '"ttt="">
        pattern = Pattern.compile("<ttt(.*?)'\"ttt(.*?)>");
        matcher = pattern.matcher(content);
        match_flag = matcher.find();
        if(match_flag)
        {
                /*
                  <body>
                    <img src="000111&quot;" ttt'"ttt=""/>
                    '&gt;
                  </body>
                 */
            System.out.println("'  \"  <  >  全部可用");
        }
    }


    public static void main(String[] args) throws IOException {

        Pattern pattern;
        Matcher matcher;
        boolean match_flag;

        final WebClient webClient = new WebClient();
        webClient.getOptions().setJavaScriptEnabled(true);
        webClient.getOptions().setCssEnabled(false);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnScriptError(false);
        webClient.getOptions().setRedirectEnabled(false);
        new WebConnectionListener(webClient);

        // 这里尝试去取我们设置的JavaScript错误处理器
        final JavaScriptEngine myEngine = new JavaScriptEngine(webClient) {
            @Override
            protected void handleJavaScriptException(final ScriptException scriptException, final boolean triggerOnError) {
                System.out.println("############");
                System.out.println(scriptException.getMessage());
                System.out.println("############");
                super.handleJavaScriptException(scriptException, triggerOnError);

            }
        };
        webClient.setJavaScriptEngine(myEngine);

        //获取页面
        try
        {
            String url ="http://127.0.0.1/dom_location_xss.php?url=1415926";
            HtmlPage page = webClient.getPage(url);
            String html = page.asXml().toLowerCase();
            System.out.println(html);

            //检测dom location href src
            pattern = Pattern.compile("(a|frame)(.*?)(href|src)=\"1415926");
            matcher = pattern.matcher(page.asXml());
            match_flag = matcher.find();
            if(match_flag)
            {
                System.out.println("note frame src or a href");
            }

            //检测dom eval
            pattern = Pattern.compile("eval(.*?)1415926");
            matcher = pattern.matcher(page.asXml());
            match_flag = matcher.find();
            if(match_flag)
            {
                System.out.println("notice eval()");
            }

            //检测dom settimeout
            pattern = Pattern.compile("settimeout(.*?)1415926");
            matcher = pattern.matcher(page.asXml());
            match_flag = matcher.find();
            if(match_flag)
            {
                System.out.println("notice settimeout()");
            }

            //检测dom eval
            pattern = Pattern.compile("location(.*?)1415926");
            matcher = pattern.matcher(page.asXml());
            match_flag = matcher.find();
            if(match_flag)
            {
                System.out.println("notice location()");
            }


        } catch (ScriptException e) {
            System.out.println(e.getFailingLine());
            System.out.println(e.getPage().asXml().toLowerCase());
            System.out.println("error page");
        }
        webClient.close();


    }
}
