import com.gargoylesoftware.htmlunit.ScriptException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class js_html_xss {
    public static void test_all_character(String content){
        Pattern pattern;
        Matcher matcher;
        boolean match_flag;
        //1415926'"<xxx'"xxx>xxx
        //html 逃逸所有符号，不能确定所在位置。有可能单引号逃逸、双引号逃逸、或者属性
        //匹配 <xxx '"xxx="">
        pattern = Pattern.compile("<xxx(.*?)'\"xxx(.*?)>");
        matcher = pattern.matcher(content);
        match_flag = matcher.find();
        if(match_flag)
        {
                /*
                  <body>
                    <img src="1415926&quot;" xxx'"xxx=""/>
                    '&gt;
                  </body>
                 */
            System.out.println("'  \"  <  >  all is available");
        }
    }


    public static void main(String[] args) throws IOException {
        Pattern pattern;
        Matcher matcher;
        boolean match_flag;

        WebClient webClient = new WebClient();
        webClient.getOptions().setJavaScriptEnabled(true);
        webClient.getOptions().setCssEnabled(false);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnScriptError(false);

        ArrayList<String> result_list = new ArrayList<>();
        result_list.add("11111111");
        result_list.add("22222222");
        if(result_list.size()>1){
            System.out.println(result_list.get(1));
            System.out.println("111111111");
        }

        //获取页面
        try
        {
            //payload，1415926'"<xxx'"xxx>xxx
            String url ="http://127.0.0.1/in_label_safe_xss.php?url=1415926'\"<xxx'\"xxx>xxx";
            HtmlPage page = webClient.getPage(url);


            //获取script里面的js
            pattern = Pattern.compile("//<!\\[CDATA\\[(.*?)//\\]\\]>",Pattern.DOTALL);
            matcher = pattern.matcher(page.asXml());
            List<String> script_list = new ArrayList<String>();
            while (matcher.find()) {
                script_list.add(matcher.group());
            }

            System.out.println(page.asXml());


            //html 逃逸尖括号
            //有会转义单双引号，但是没有转义尖括号，匹配 <xxx \\'\\\"xxx="">
            pattern = Pattern.compile("<xxx (.*?)xxx=\"\"(.*?)>");
            matcher = pattern.matcher(page.asXml());
            match_flag = matcher.find();
            if(match_flag)
            {
            /*
                <h1>
                  1415926'"
                  <xxx '"xxx="">
                    xxx
                  </xxx>
                </h1>
            */
                System.out.println("out label <> can escape.");
            }

            //html 双引号逃逸
            //匹配 <xxx '"xxx="">.*?"&gt;
            //http://127.0.0.1/in_label_value_single_xss.php?url=1415926'"<xxx'"xxx>xxx
            pattern = Pattern.compile("xxx(.*?)\"(.*?)xxx=\"\"(.*?)>.*?\"&gt;",Pattern.DOTALL);
            matcher = pattern.matcher(page.asXml());
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
                System.out.println("in label value html-xss 双引号逃逸");
                test_all_character(page.asXml());
            }

            //html 单引号逃逸
            //匹配 <img src="1415926" "<xxx'"xxx=""/>.*?'&gt;
            //http://127.0.0.1/in_label_value_double_xss.php?url=1415926'"<xxx'"xxx>xxx
            pattern = Pattern.compile("xxx(.*?)'(.*?)xxx=\"\"(.*?)>.*?'&gt;",Pattern.DOTALL);
            matcher = pattern.matcher(page.asXml());
            match_flag = matcher.find();
            if(match_flag)
            {
                /*
                  <body>
                    <img src="1415926" "<xxx'"xxx=""/>
                    '&gt;
                  </body>
                 */
                System.out.println("in label value html-xss 单引号逃逸");
                test_all_character(page.asXml());
            }

            //html attribute
            //匹配 <xxx'"xxx=""/>.*?xxx&gt;
            //http://127.0.0.1/in_label_attr_xss.php?url=1415926'"<xxx'"xxx>xxx
            pattern = Pattern.compile("xxx(.*?)'(.*?)xxx=\"\"(.*?)>.*?xxx&gt;",Pattern.DOTALL);
            matcher = pattern.matcher(page.asXml());
            match_flag = matcher.find();
            if(match_flag)
            {
                /*
                  <body>
                    <img src="1" 1415926'"<xxx'"xxx=""/>
                    xxx&gt;
                  </body>
                 */
                System.out.println("in label attribute html-xss 逃逸");
                test_all_character(page.asXml());
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
                    System.out.println(" js-xss 没有分隔符");
                    test_all_character(page.asXml());
                }

                //第一个双引号出现的位置在第一个单引号的位置后面，则说明是单引号包含的
                if( (double_position>-1 && single_position>-1 && double_position > single_position) || single_position>-1)
                {
                    pattern = Pattern.compile("(.*?)1415926(.*?)'(.*?)xxx(.*?)xxx");
                    matcher = pattern.matcher(page.asXml());
                    match_flag = matcher.find();
                    if(match_flag)
                    {
                        System.out.println(" js-xss 单引号 逃逸");
                        test_all_character(page.asXml());
                    }
                }

                //第一个出现单引号的位置在第一个双引号的位置后面，则说明是双引号包含的
                if((double_position>-1 && single_position>-1 && double_position < single_position) || double_position>-1)
                {
                    pattern = Pattern.compile("(.*?)1415926(.*?)\"(.*?)xxx(.*?)xxx");
                    matcher = pattern.matcher(page.asXml());
                    match_flag = matcher.find();
                    if(match_flag)
                    {
                        System.out.println(" js-xss 双引号 逃逸");
                        test_all_character(page.asXml());
                    }
                }

            }

            test_all_character(page.asXml());


        } catch (ScriptException e) {
            System.out.println(e.getFailingLine());
            System.out.println(e.getPage().asXml());
            System.out.println("error page");
        }
        webClient.close();


    }
}
